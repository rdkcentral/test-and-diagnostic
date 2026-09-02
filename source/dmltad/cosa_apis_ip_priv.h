#ifndef _COSA_APIS_IP_PRIV_H
#define _COSA_APIS_IP_PRIV_H

#include "plugin_main_apis.h"
#include "ccsp_base_api.h"

#ifndef CCSP_COMPONENT_ID_NOTIFY_COMP
#define CCSP_COMPONENT_ID_NOTIFY_COMP                       0x0000000C
#endif

#define DEF_SIZE                32
#define DEF_SIZE_128            128

void getDiagnosticState(uint DiagType, char* DiagState);

extern BOOL g_Tr143SpeedTestTestUsable;

typedef enum tr143_diag_e {
    TR143_DIAGNOSTIC_None = 0,
    TR143_DIAGNOSTIC_Requested,
    TR143_DIAGNOSTIC_Completed,
    TR143_DIAGNOSTIC_Error_InitConnectionFailed,
    TR143_DIAGNOSTIC_Error_NoResponse,
    TR143_DIAGNOSTIC_Error_TransferFailed,
    TR143_DIAGNOSTIC_Error_PasswordRequestFailed,
    TR143_DIAGNOSTIC_Error_LoginFailed,
    TR143_DIAGNOSTIC_Error_NoTransferMode,
    TR143_DIAGNOSTIC_Error_NoPASV,
    TR143_DIAGNOSTIC_Error_IncorrectSize,
    TR143_DIAGNOSTIC_Error_Timeout,
    TR143_DIAGNOSTIC_Canceled,
    TR143_DIAGNOSTIC_Error_Internal,
    TR143_DIAGNOSTIC_Error_UDPEcho_True,
    TR143_DIAGNOSTIC_Error_UDPEcho_False,
} tr143_diag_t;

#endif
