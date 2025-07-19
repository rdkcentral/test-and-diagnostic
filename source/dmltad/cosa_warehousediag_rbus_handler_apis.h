#ifndef  _WHDIAG_RBUS_HANDLER_APIS_H
#define  _WHDIAG_RBUS_HANDLER_APIS_H

#include <rbus/rbus.h>
rbusError_t WAREHOUSEDIAG_GetHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusGetHandlerOptions_t* opts);
rbusError_t WAREHOUSEDIAG_SetHandler(rbusHandle_t handle, rbusProperty_t property,
                                                        rbusSetHandlerOptions_t* opts);

#endif