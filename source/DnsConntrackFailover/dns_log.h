/*
 * dns_log.h
 *
 * Leveled logging to stderr.
 */

#ifndef DNS_LOG_H
#define DNS_LOG_H

#include <stdio.h>

#define LOG_INFO(fmt, ...)  fprintf(stderr, "INFO: " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

#endif /* DNS_LOG_H */

