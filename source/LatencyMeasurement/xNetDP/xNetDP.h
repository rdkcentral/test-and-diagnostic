#ifndef XNETDP_H
#define XNETDP_H

#include <stdbool.h>

typedef struct xNetDPConfig
{
    bool dbg_mode;
    bool verbose_mode;
    int report_type;
    int report_interval;
    char report_name[256];
    char log_file[64];
} xNetDPConfig;

int xNetDP_Run(const xNetDPConfig *config);
void xNetDP_UpdateConfig(const xNetDPConfig *config);
void xNetDP_RequestStop(void);

#endif