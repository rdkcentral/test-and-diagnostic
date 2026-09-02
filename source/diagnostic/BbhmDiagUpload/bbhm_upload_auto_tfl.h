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
    module: bbhm_upload_auto_tfl.h — auto TestFileLength when SRU == 0

    AutoTfl_Start / Finish / MarkManual / TryManual / Reset — train & reuse TFL
    AutoTfl_TriggerOnWanStatus — once at init: on wan-status=started, ACS Requested
**********************************************************************/

#ifndef  _BBHM_UPLOAD_AUTO_TFL_H_
#define  _BBHM_UPLOAD_AUTO_TFL_H_

#include "bbhm_upload_global.h"

/* 1 MB default: clears manual + trained size → next Requested calibrates. */
#define  UPLOAD_TFL_DEFAULT_BYTES                 1000000

void AutoTfl_Reset(void);
void AutoTfl_MarkManual(ULONG testFileLength);
BOOL AutoTfl_TryManual(PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo);
void AutoTfl_Start(PDSLH_TR143_UPLOAD_DIAG_INFO pUploadInfo);
void AutoTfl_Finish
    (
        PBBHM_UPLOAD_DIAG_OBJECT      pMyObject,
        PDSLH_TR143_UPLOAD_DIAG_STATS pStats
    );

/* On first wan-status=started: set Requested + Commit (same as ACS); task exits. */
void AutoTfl_TriggerOnWanStatus(void);

#endif /* _BBHM_UPLOAD_AUTO_TFL_H_ */
