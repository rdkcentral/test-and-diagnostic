/*
 * If not stated otherwise in this file or this component's LICENSE file
 * the following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
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

#ifndef NTP_SYNC_MONITOR_H
#define NTP_SYNC_MONITOR_H

/*
 * ntp_sync_monitor
 *
 * Daemon-agnostic NTP clock observer hosted inside CcspTandDSsp. Reads kernel
 * clock-discipline state via ntp_adjtime()/adjtimex() (works whether chrony or
 * ntpd is the active client). Provides two threads:
 *
 *   Thread 1 (first-sync)  : polls the kernel every 1s until the first NTP sync,
 *                            logs the initial offset/frequency, writes the
 *                            sync-notification side effects (ntp_status=3,
 *                            ntp_time_sync=1, /tmp/clock-event,
 *                            /tmp/.ntp_time_synced, device_first_use_date), sets
 *                            a marker, then exits. Marker-gated: never re-runs.
 *
 *   Thread 2 (periodic)    : every 10 minutes reads offset/frequency and emits
 *                            them to Telemetry 2.0. Uses timerfd (drift-free,
 *                            signal-safe). Runs independently of Thread 1.
 *
 * Both offsets are reported under the single T2 marker SYS_INFO_NTP_DELTA_split.
 *
 * ntp_sync_monitor_start() MUST be called unconditionally from ssp_main.c,
 * regardless of EthWAN, extender, or RFC (chrony/ntpd) selection.
 */
void ntp_sync_monitor_start(void);

#endif /* NTP_SYNC_MONITOR_H */
