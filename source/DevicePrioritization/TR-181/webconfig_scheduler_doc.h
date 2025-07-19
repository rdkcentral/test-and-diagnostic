/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __WEBCONFIG_SCHEDULER_DOC_H__
#define __WEBCONFIG_SCHEDULER_DOC_H__

#ifdef RDK_SCHEDULER_ENABLED

#include <stdint.h>
#include <stdlib.h>
#include <msgpack.h>
#include "scheduler_interface.h"
#include "device_prio_webconfig_apis.h"
#include "webconfig_helper_apis.h"
#include "ccsp_trace.h"

#define WEEKLY_SCHEDULE "weekly"
#define ABSOLUTE_SCHEDULE "absolute"
#define RELATIVE_TIME_STR "time"
#define UNIX_TIME_STR "unix_time"
#define INDEXES_STR "indexes"
/* Currently SCHEDULER will not do any validation on time_zone string */
#define TIME_ZONE "time_zone" /* REF: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones */

enum {
    SCHEDULER_INFO_OK = 0,
    SCHEDULER_INFO_WEEKLY_ERR,
    SCHEDULER_INFO_ABSOLUTE_ERR,
    SCHEDULER_INFO_ACTIONS_ERR,
    SCHEDULER_INFO_TIMEZONE_ERR
};

typedef struct scheduler_doc{
    schedule_info_t*  scheduler_info;       
    char*             subdoc_name;
    uint32_t          version;
    uint16_t          transaction_id;
} scheduler_doc_t;

/**
 *  This function converts a msgpack buffer into an scheduler_doc_t structure
 *  if possible.
 *
 *  @param buf the buffer to convert
 *  @param len the length of the buffer in bytes
 *
 *  @return NULL on error, success otherwise
 */
scheduler_doc_t* scheduler_doc_convert( const void *buf, size_t len );

/**
 *  This function destroys an scheduler_doc_t object.
 *
 *  @param sd the scheduler_doc_t to destroy
 */
void scheduler_doc_destroy( scheduler_doc_t *sd );

#endif //#ifdef RDK_SCHEDULER_ENABLED

#endif

