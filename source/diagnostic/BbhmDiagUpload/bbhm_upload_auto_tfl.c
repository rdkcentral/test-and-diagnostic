/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*********************************************************************************
If not stated otherwise in this file or this component's Licenses.txt file the
* following copyright and licenses apply:
*
* Copyright 2026 Deutsche Telekom AG.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.

*********************************************************************************/

/**********************************************************************
    module: bbhm_upload_auto_tfl.c

    Auto TestFileLength when SRU == 0: train payload size so BOM→EOM is 5–7 s.

    Training (on each upload Requested):
      - AutoTfl_Start / AutoTfl_Finish via updateTestFileLength()
      - Initial size from wan_physical_ifname (+ XGS/GPON PhysicalMedia for pon/veip)
      - In band → lock and reuse; outside → adjust / shrink / ScheduleNext
      - After bDone, later Requested only reuses storedBytes (no retrain)

    Boot kick (once per process):
      - AutoTfl_TriggerOnWanStatus() from COSA_Diag_Init
      - Wait for sysevent wan-status=started, then same flow as ACS Requested
        (set DiagnosticsState + UploadDiagnostics_Commit); waiter task exits
**********************************************************************/

#include "bbhm_upload_auto_tfl.h"
#include "cosa_diagnostic_apis.h"
#include "safec_lib_common.h"
#include <syscfg/syscfg.h>
#include <sysevent/sysevent.h>
#include <string.h>
#include <strings.h>

#define  AUTOTFL_MIN_SEC                 5.0
#define  AUTOTFL_MAX_SEC                 7.0
#define  AUTOTFL_MAX_ROUNDS              7
#define  AUTOTFL_WINDOW_MARGIN_SEC       2.0   /* under TimeBasedTestDuration (~10s) */
#define  AUTOTFL_DEFAULT_WINDOW_SEC      10

/*
 * Initial TFL when SRU==0 (SRU>0 → rate×6 s in updateTestFileLength).
 * Mid-band starts; AutoTfl grows/shrinks into 5–7 s.
 */
#define  AUTOTFL_INITIAL_XGSPON             750000000UL
#define  AUTOTFL_INITIAL_GPON               100000000UL
#define  AUTOTFL_INITIAL_VDSL                25000000UL
#define  AUTOTFL_INITIAL_WANOE               25000000UL
#define  AUTOTFL_INITIAL_DEFAULT             25000000UL
#define  AUTOTFL_INITIAL_ADSL                 1000000UL

#define  SYSCFG_WAN_PHYSICAL_IFNAME    "wan_physical_ifname"
#define  GPONMGR_COMPONENT_NAME        "eRT.com.cisco.spvtg.ccsp.gponmanager"
#define  GPONMGR_DBUS_PATH             "/com/cisco/spvtg/ccsp/gponmanager"
#define  AUTOTFL_PHYMEDIA_MAX            4

/* After wan-status=started, wait for route/DNS/firewall before Commit. */
#define  AUTOTFL_WAN_SETTLE_MS           30000

typedef struct
{
    BOOL    bActive;
    BOOL    bDone;
    BOOL    bResume;          /* follow-up Requested from ScheduleNext */
    BOOL    bManual;
    ULONG   storedBytes;
    ULONG   runsCompleted;
}
AUTOTFL_STATE;

static AUTOTFL_STATE g_autoTfl = { 0 };

extern PBBHM_UPLOAD_DIAG_OBJECT g_DiagUploadObj;
ULONG UploadDiagnostics_Commit(ANSC_HANDLE hInsContext);

/* ---- helpers ---- */

/* Floor at 1 MB; no policy max — TFL may grow with link rate (DM type is ULONG). */
static ULONG
ClampBytes(unsigned long long n)
{
    if (n < (unsigned long long)UPLOAD_TFL_DEFAULT_BYTES)
        return UPLOAD_TFL_DEFAULT_BYTES;
    if (n > (unsigned long long)(~(ULONG)0))
        return ~(ULONG)0;
    return (ULONG)n;
}

/*
 * Scan PhysicalMedia.{i}:
 *   XGS-PON (Enable true or false) → TRUE  (AUTOTFL_INITIAL_XGSPON)
 *   GPON + Enable=true             → FALSE (AUTOTFL_INITIAL_GPON), stop
 *   GPON + Enable=false            → skip, keep looking (dual-media)
 * Missing .2 (9005/9007) ends the scan.
 */
static BOOL
IsXgsPon(void)
{
    ULONG inst;

    for (inst = 1; inst <= (ULONG)AUTOTFL_PHYMEDIA_MAX; inst++)
    {
        char    enableDm[96];
        char    ponModeDm[96];
        char    enableVal[32];
        char    ponModeVal[64];
        BOOL    bEnabled;
        errno_t rc;

        rc = sprintf_s(enableDm, sizeof(enableDm),
                "Device.X_RDK_ONT.PhysicalMedia.%lu.Enable", (unsigned long)inst);
        if (rc < EOK)
        {
            ERR_CHK(rc);
            continue;
        }

        /* Missing instance (9005/9007) → no more rows. */
        if (ANSC_STATUS_SUCCESS != Tad_GetParamString(GPONMGR_COMPONENT_NAME,
                GPONMGR_DBUS_PATH, enableDm, enableVal, sizeof(enableVal)))
            break;

        bEnabled = (strcasecmp(enableVal, "true") == 0);

        rc = sprintf_s(ponModeDm, sizeof(ponModeDm),
                "Device.X_RDK_ONT.PhysicalMedia.%lu.PonMode", (unsigned long)inst);
        if (rc < EOK)
        {
            ERR_CHK(rc);
            continue;
        }

        if (ANSC_STATUS_SUCCESS != Tad_GetParamString(GPONMGR_COMPONENT_NAME,
                GPONMGR_DBUS_PATH, ponModeDm, ponModeVal, sizeof(ponModeVal)))
            continue;

        CcspTraceInfo(("UploadDiag AutoTfl: PhysicalMedia.%lu Enable='%s' PonMode='%s'\n",
                (unsigned long)inst, enableVal, ponModeVal));

        if (strcasecmp(ponModeVal, "XGS-PON") == 0
                || strcasecmp(ponModeVal, "XGSPON") == 0)
            return TRUE;

        /* Enabled GPON → not XGS; do not scan further. */
        if (bEnabled && strcasecmp(ponModeVal, "GPON") == 0)
            return FALSE;

        /* Disabled GPON / other modes → keep scanning. */
    }

    return FALSE;
}

static ULONG
GetInitialBytes(void)
{
    char ifname[64] = { 0 };

    if (syscfg_get(NULL, SYSCFG_WAN_PHYSICAL_IFNAME, ifname, sizeof(ifname)) != 0
            || ifname[0] == '\0')
        return AUTOTFL_INITIAL_DEFAULT;

    if (strstr(ifname, "pon") == ifname || strstr(ifname, "veip") == ifname)
        return IsXgsPon() ? AUTOTFL_INITIAL_XGSPON : AUTOTFL_INITIAL_GPON;

    if (strcmp(ifname, "nas10") == 0)
        return AUTOTFL_INITIAL_VDSL;

    if (strcmp(ifname, "nas0") == 0)
        return AUTOTFL_INITIAL_ADSL;

    if (strstr(ifname, "eth") == ifname)
        return AUTOTFL_INITIAL_WANOE;

    return AUTOTFL_INITIAL_DEFAULT;
}

/*
 * next ≈ bytes * targetSec / measuredSec, then:
 *   - force move if prediction did not change direction enough
 *   - never exceed rate * (testWindow - margin) so PUT can get 200 OK
 */
static ULONG
NextBytes(ULONG bytes, DOUBLE measuredSec, ULONG windowSec)
{
    DOUBLE             target;
    DOUBLE             safeSec;
    unsigned long long next;
    unsigned long long cap;

    if (bytes == 0)
        bytes = GetInitialBytes();
    if (measuredSec < 0.1)
        measuredSec = 0.1;
    if (windowSec == 0)
        windowSec = AUTOTFL_DEFAULT_WINDOW_SEC;

    target = (measuredSec > AUTOTFL_MAX_SEC) ? AUTOTFL_MAX_SEC : AUTOTFL_MIN_SEC;
    next   = (unsigned long long)(((DOUBLE)bytes / measuredSec) * target);

    /*
     * Guarantee a meaningful step when the rate formula barely moved size:
     *   too slow (>7 s) but next still >= bytes → force 25% cut
     *   too fast (<5 s) but next still <= bytes → force 2x grow
     */
    if (measuredSec > AUTOTFL_MAX_SEC && next >= bytes)
        next = (unsigned long long)bytes * 3ULL / 4ULL;
    else if (measuredSec < AUTOTFL_MIN_SEC && next <= bytes)
        next = (unsigned long long)bytes * 2ULL;

    /*
     * Cap next size so the PUT can finish inside TimeBasedTestDuration.
     * Use (window − 2 s) headroom; otherwise send loop may truncate the body
     * and the server never returns 200 OK.
     *   cap = measured_rate × safeSec
     */
    safeSec = (DOUBLE)windowSec - AUTOTFL_WINDOW_MARGIN_SEC;
    if (safeSec < AUTOTFL_MIN_SEC)
        safeSec = AUTOTFL_MIN_SEC;

    cap = (unsigned long long)(((DOUBLE)bytes / measuredSec) * safeSec);
    if (next > cap)
        next = cap;

    return ClampBytes(next);
}

static void
AbortAutoTfl(const char *why)
{
    CcspTraceWarning(("UploadDiag AutoTfl: abort - %s\n", why ? why : "unknown"));
    g_autoTfl.bActive       = FALSE;
    g_autoTfl.bResume       = FALSE;
    g_autoTfl.runsCompleted = 0;
}

/*
 * Mid-training only: start another upload with a new TestFileLength.
 * Unlike AutoTfl_RequestOnWanStarted(), this skips DM Set/Commit and calls
 * StartDiag directly (upload must already be idle).
 */
static ANSC_STATUS
ScheduleNext(PBBHM_UPLOAD_DIAG_OBJECT pObj, ULONG bytes)
{
    if (pObj == NULL || g_DiagUploadObj == NULL || g_DiagUploadObj->bUpDiagOn)
        return ANSC_STATUS_FAILURE;

    /* In-place on Bbhm UploadDiagInfo; bResume so Start keeps this TFL. */
    pObj->UploadDiagInfo.TestFileLength   = bytes;
    pObj->UploadDiagInfo.DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
    g_autoTfl.bResume = TRUE;

    return g_DiagUploadObj->StartDiag((ANSC_HANDLE)g_DiagUploadObj);
}

static void
LockSize(ULONG bytes)
{
    g_autoTfl.storedBytes = ClampBytes(bytes);
    g_autoTfl.bDone       = TRUE;
    g_autoTfl.bActive     = FALSE;
    g_autoTfl.bResume     = FALSE;
    g_autoTfl.runsCompleted = 0;
    CcspTraceInfo(("UploadDiag AutoTfl: trained TestFileLength=%lu\n", g_autoTfl.storedBytes));
}

static void
RetrySmaller(PBBHM_UPLOAD_DIAG_OBJECT pObj, ULONG curBytes)
{
    ULONG next;

    if (g_autoTfl.runsCompleted + 1 >= (ULONG)AUTOTFL_MAX_ROUNDS
            || curBytes <= UPLOAD_TFL_DEFAULT_BYTES)
    {
        AbortAutoTfl("no shrink retry left");
        return;
    }

    next = ClampBytes((unsigned long long)curBytes / 2ULL);
    if (next >= curBytes)
        next = UPLOAD_TFL_DEFAULT_BYTES;

    CcspTraceWarning(("UploadDiag AutoTfl: shrink %lu -> %lu after failure, re-Request\n",
            (unsigned long)curBytes, (unsigned long)next));

    g_autoTfl.runsCompleted++;
    if (ScheduleNext(pObj, next) != ANSC_STATUS_SUCCESS)
        AbortAutoTfl("schedule failed");
}

/* ---- public API ---- */

void
AutoTfl_Reset(void)
{
    memset(&g_autoTfl, 0, sizeof(g_autoTfl));
}

void
AutoTfl_MarkManual(ULONG testFileLength)
{
    if (testFileLength == UPLOAD_TFL_DEFAULT_BYTES)
    {
        AutoTfl_Reset();
        CcspTraceInfo(("UploadDiag AutoTfl: TFL default → clear; next Requested will auto-select TFL\n"));
        return;
    }

    g_autoTfl.bManual = TRUE;
    g_autoTfl.bActive = FALSE;
    CcspTraceInfo(("UploadDiag AutoTfl: TFL=%lu manual (skip auto TFL)\n", testFileLength));
}

BOOL
AutoTfl_TryManual(PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo)
{
    if (pUploadInfo == NULL || !g_autoTfl.bManual || pUploadInfo->TestFileLength == 0)
        return FALSE;

    g_autoTfl.bActive = FALSE;
    g_autoTfl.bResume = FALSE;
    CcspTraceInfo(("UploadDiag AutoTfl: use manual TFL=%lu\n", pUploadInfo->TestFileLength));
    return TRUE;
}

void
AutoTfl_Start(PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo)
{
    ULONG initial;
    ULONG runNo;

    if (pUploadInfo == NULL)
        return;

    if (g_autoTfl.bDone && g_autoTfl.storedBytes >= UPLOAD_TFL_DEFAULT_BYTES)
    {
        g_autoTfl.bActive = FALSE;
        g_autoTfl.bResume = FALSE;
        pUploadInfo->TestFileLength = g_autoTfl.storedBytes;
        CcspTraceInfo(("UploadDiag AutoTfl: reuse TFL=%lu\n", g_autoTfl.storedBytes));
        return;
    }

    g_autoTfl.bActive = TRUE;

    if (!g_autoTfl.bResume)
    {
        initial = GetInitialBytes();
        g_autoTfl.runsCompleted = 0;
        pUploadInfo->TestFileLength = initial;
    }

    /* Log every training attempt (first and re-Request) so field can see which run is active. */
    runNo = g_autoTfl.runsCompleted + 1;
    CcspTraceInfo(("UploadDiag AutoTfl: run %lu/%d starting, TFL=%lu\n",
            (unsigned long)runNo, AUTOTFL_MAX_ROUNDS,
            (unsigned long)pUploadInfo->TestFileLength));

    g_autoTfl.bResume = FALSE;
}

void
AutoTfl_Finish
    (
        PBBHM_UPLOAD_DIAG_OBJECT      pMyObject,
        PDSLH_TR143_UPLOAD_DIAG_STATS pStats
    )
{
    DOUBLE sec;
    ULONG  bytes;
    ULONG  next;
    ULONG  window;
    ULONG  state;
    ULONG  runNo;

    if (!g_autoTfl.bActive || pMyObject == NULL || pStats == NULL)
        return;

    bytes = pMyObject->UploadDiagInfo.TestFileLength;
    state = pStats->DiagStates;

    /* ---- failure path ---- */
    if (state != DSLH_TR143_DIAGNOSTIC_Completed)
    {
        BOOL canShrink = (state == DSLH_TR143_DIAGNOSTIC_Error_TransferFailed
                || state == DSLH_TR143_DIAGNOSTIC_Error_Timeout
                || state == DSLH_TR143_DIAGNOSTIC_Error_IncorrectSize);

        /* Early fail / server issues → abort. Late transfer fail → shrink. */
        if (canShrink && bytes > 0 && pStats->TestBytesSent * 10 >= bytes)
        {
            RetrySmaller(pMyObject, bytes);
            return;
        }

        CcspTraceWarning(("UploadDiag AutoTfl: fail DiagState=%lu sent=%lu/%lu — abort "
                "(next Requested will retrain)\n",
                (unsigned long)state,
                (unsigned long)pStats->TestBytesSent,
                (unsigned long)bytes));
        AbortAutoTfl("upload error / server");
        return;
    }

    /* ---- success path ---- */
    window = pMyObject->UploadDiagInfo.TimeBasedTestDuration;
    if (window == 0)
        window = AUTOTFL_DEFAULT_WINDOW_SEC;

    sec = CalculateTimeDifference((USER_SYSTEM_TIME*)&pStats->EOMTime,
            (USER_SYSTEM_TIME*)&pStats->BOMTime);

    runNo = g_autoTfl.runsCompleted + 1; /* 1-based for logs */
    CcspTraceInfo(("UploadDiag AutoTfl: run %lu/%d done, duration=%.3f s, TFL=%lu\n",
            (unsigned long)runNo, AUTOTFL_MAX_ROUNDS, sec, (unsigned long)bytes));

    if (sec >= AUTOTFL_MIN_SEC && sec <= AUTOTFL_MAX_SEC)
    {
        LockSize(bytes);
        return;
    }

    if (g_autoTfl.runsCompleted + 1 >= (ULONG)AUTOTFL_MAX_ROUNDS)
    {
        /* Already outside 5–7 s (in-band returned above). Scale once and lock. */
        next = NextBytes(bytes, sec, window);
        CcspTraceInfo(("UploadDiag AutoTfl: last round outside band "
                "(%.3f s), lock adjusted TFL %lu -> %lu\n",
                sec, (unsigned long)bytes, (unsigned long)next));
        LockSize(next);
        return;
    }

    next = NextBytes(bytes, sec, window);
    CcspTraceWarning(("UploadDiag AutoTfl: adjust TFL %lu -> %lu (duration=%.3f s), re-Request\n",
            (unsigned long)bytes, (unsigned long)next, sec));

    g_autoTfl.runsCompleted++;
    if (ScheduleNext(pMyObject, next) != ANSC_STATUS_SUCCESS)
        AbortAutoTfl("schedule failed");
}

/*
 * ---- Boot: first wan-status=started → ACS-style Requested, then stop ----
 *
 * Flow matches ACS/WebPA setting DiagnosticsState=Requested:
 *   RequestOnWanStarted → set state on DM upload info → UploadDiagnostics_Commit
 *   Commit → IfAddr / TestUsable / CosaDmlDiagScheduleDiagnostic → StartDiag
 *   → updateTestFileLength → AutoTfl_Start (train or reuse)
 *
 * ScheduleNext is different: only used between training rounds (Bbhm StartDiag).
 */

/* Same as a successful ACS Set of DiagnosticsState=Requested, then Commit. */
static void
AutoTfl_RequestOnWanStarted(void)
{
    PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo;

    if (g_pCosaBEManager == NULL || g_pCosaBEManager->hDiag == NULL)
        return;

    pUploadInfo = ((PCOSA_DATAMODEL_DIAG)g_pCosaBEManager->hDiag)->hDiagUploadInfo;
    if (pUploadInfo == NULL)
        return;

    /* UploadDiagnostics_SetParamUlongValue("DiagnosticsState") also rejects this. */
    if (g_DiagUploadObj != NULL && g_DiagUploadObj->bUpDiagOn)
    {
        CcspTraceWarning(("UploadDiag AutoTfl: wan-status=started, upload busy — skip\n"));
        return;
    }

    pUploadInfo->DiagnosticsState = DSLH_TR143_DIAGNOSTIC_Requested;
    CcspTraceInfo(("UploadDiag AutoTfl: wan-status=started → Requested (URL=%s)\n",
            pUploadInfo->UploadURL[0] ? pUploadInfo->UploadURL : "(empty)"));
    /* Commit: resolve IfAddr, check TestUsable, schedule/start upload. */
    UploadDiagnostics_Commit(NULL);
}

/*
 * One-shot waiter: register for wan-status, settle, fire Requested once, exit.
 * wan-status=started can race ahead of route/DNS/firewall (InitConnectionFailed);
 * settle gives the stack time to become usable.
 */
static ANSC_STATUS
AutoTfl_WanStatusWaitTask(ANSC_HANDLE hUnused)
{
    int         fd = -1;
    token_t     token;
    async_id_t  asyncid;
    char        wanStatus[64];

    UNREFERENCED_PARAMETER(hUnused);

    fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION,
            "AutoTflWanStatus", &token);
    if (fd < 0)
    {
        CcspTraceWarning(("UploadDiag AutoTfl: sysevent_open failed\n"));
        return ANSC_STATUS_FAILURE;
    }

    /* Event-driven wait (not a poll loop); task ends after first started. */
    sysevent_set_options(fd, token, "wan-status", TUPLE_FLAG_EVENT);
    sysevent_setnotification(fd, token, "wan-status", &asyncid);

    /* DM upload object must exist before Commit. */
    while (g_pCosaBEManager == NULL || g_pCosaBEManager->hDiag == NULL)
        AnscSleep(1000);

    memset(wanStatus, 0, sizeof(wanStatus));
    if (sysevent_get(fd, token, "wan-status", wanStatus, sizeof(wanStatus)) == 0
            && strcasecmp(wanStatus, "started") == 0)
        goto wan_started;

    for (;;)
    {
        char        name[64] = { 0 };
        char        val[64]  = { 0 };
        int         namelen  = (int)sizeof(name);
        int         vallen   = (int)sizeof(val);
        async_id_t  getid;
        int         err;

        err = sysevent_getnotification(fd, token, name, &namelen, val, &vallen, &getid);
        if (err != 0)
        {
            AnscSleep(1000);
            continue;
        }

        if (strcasecmp(name, "wan-status") == 0
                && strcasecmp(val, "started") == 0)
            break;
    }

wan_started:
    CcspTraceInfo(("UploadDiag AutoTfl: wan-status=started, settle %d ms before Requested\n",
            AUTOTFL_WAN_SETTLE_MS));
    AnscSleep(AUTOTFL_WAN_SETTLE_MS);
    AutoTfl_RequestOnWanStarted();
    sysevent_close(fd, token);
    return ANSC_STATUS_SUCCESS;
}

/* Called from COSA_Diag_Init; spawns the one-shot wan-status waiter above. */
void
AutoTfl_TriggerOnWanStatus(void)
{
    AnscSpawnTask
        (
            (void *)AutoTfl_WanStatusWaitTask,
            (ANSC_HANDLE)NULL,
            "AutoTflWanStatus"
        );
}
