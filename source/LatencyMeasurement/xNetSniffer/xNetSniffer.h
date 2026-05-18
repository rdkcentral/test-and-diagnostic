#ifndef XNETSNIFFER_H
#define XNETSNIFFER_H

#include <stdbool.h>

typedef struct xNetSnifferConfig
{
    bool dbg_mode;
    char interface_name[32];
    char log_file[64];
    char ipv4_prefix[128];
    char ipv6_prefix[128];
} xNetSnifferConfig;

int xNetSniffer_Run(const xNetSnifferConfig *config);
void xNetSniffer_RequestStop(void);

#endif