/*
 * TR-143 upload/download diagnostics — minimal private helpers (no DT iperf3 / setDefaultURL).
 */
#include "ansc_platform.h"
#include "cosa_apis_ip_priv.h"
#include "cosa_diagnostic_apis.h"

BOOL g_Tr143SpeedTestTestUsable = TRUE;

void getDiagnosticState(uint DiagType, char* DiagState)
{
    uint state;

    if (DiagState == NULL)
        return;

    if (DiagType == DSLH_DIAGNOSTIC_TYPE_Download)
    {
        PDSLH_TR143_DOWNLOAD_DIAG_STATS pDownloadDiagStats = NULL;

        pDownloadDiagStats = (PDSLH_TR143_DOWNLOAD_DIAG_STATS)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_Download);

        if (pDownloadDiagStats)
        {
            state = (uint)pDownloadDiagStats->DiagStates;
        }
        else
        {
            AnscTraceWarning(("Download Diagnostics---Failed to get DiagnosticsState!\n"));
            state = TR143_DIAGNOSTIC_None;
        }
    }
    else if (DiagType == DSLH_DIAGNOSTIC_TYPE_Upload)
    {
        PDSLH_TR143_UPLOAD_DIAG_STATS pUploadDiagStats = NULL;

        pUploadDiagStats = (PDSLH_TR143_UPLOAD_DIAG_STATS)CosaDmlDiagGetResults(DSLH_DIAGNOSTIC_TYPE_Upload);

        if ( pUploadDiagStats )
        {
            state = pUploadDiagStats->DiagStates;
        }
        else
        {
            AnscTraceWarning(("Upload Diagnostics---Failed to get DiagnosticsState!\n"));
            state = TR143_DIAGNOSTIC_None;
        }
    }
    else
    {
        state = TR143_DIAGNOSTIC_None;
    }

    switch (state)
    {
        case TR143_DIAGNOSTIC_None:
            strncpy(DiagState, "None", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Requested:
            strncpy(DiagState, "Requested", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Completed:
            strncpy(DiagState, "Completed", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Canceled:
            strncpy(DiagState, "Canceled", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Error_InitConnectionFailed:
            strncpy(DiagState, "Error_InitConnectionFailed", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Error_NoResponse:
            strncpy(DiagState, "Error_NoResponse", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Error_TransferFailed:
            strncpy(DiagState, "Error_TransferFailed", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Error_PasswordRequestFailed:
        case TR143_DIAGNOSTIC_Error_LoginFailed:
        case TR143_DIAGNOSTIC_Error_NoTransferMode:
        case TR143_DIAGNOSTIC_Error_NoPASV:
        case TR143_DIAGNOSTIC_Error_IncorrectSize:
        case TR143_DIAGNOSTIC_Error_Timeout:
        case TR143_DIAGNOSTIC_Error_Internal:
            strncpy(DiagState, "Error_Internal", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Error_UDPEcho_True:
            strncpy(DiagState, "true", DEF_SIZE);
            break;
        case TR143_DIAGNOSTIC_Error_UDPEcho_False:
            strncpy(DiagState, "false", DEF_SIZE);
            break;
        default:
            strncpy(DiagState, "None", DEF_SIZE);
            break;
    }

    DiagState[DEF_SIZE - 1] = '\0';
}
