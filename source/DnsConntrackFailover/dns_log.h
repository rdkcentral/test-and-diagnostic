/*
 * dns_log.h
 *
 * Leveled logging via the RDK logger, which routes through the configured
 * /rdklogs/logs directory via the logger configuration. 
 */

#ifndef DNS_LOG_H
#define DNS_LOG_H

#include "rdk_debug.h"

#define DNS_FAILOVER_LOG_MODULE "LOG.RDK.DNSFAILOVERMANAGER"

#define LOG_INFO(fmt, ...)  RDK_LOG(RDK_LOG_INFO,  DNS_FAILOVER_LOG_MODULE, fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  RDK_LOG(RDK_LOG_WARN,  DNS_FAILOVER_LOG_MODULE, fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   RDK_LOG(RDK_LOG_ERROR, DNS_FAILOVER_LOG_MODULE, fmt "\n", ##__VA_ARGS__)

#endif /* DNS_LOG_H */

