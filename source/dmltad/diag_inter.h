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

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/*
 * diag_inter.h - internal definitions.
 * leichen2@cisco.com, Mar 2013, Initialize
 */
#ifndef __DIAG_INTER_H__
#define __DIAG_INTER_H__

#include <pthread.h>
#include "diag.h"

typedef struct diag_obj_s diag_obj_t;

typedef struct diag_ops {
    /* input: @diag, @cfg
     * output: @stat, error code (as return) */
    diag_err_t (*start)(diag_obj_t *diag, const diag_cfg_t *cfg, diag_stat_t *stat);
    diag_err_t (*stop)(diag_obj_t *diag);

    /* these hooks are optional */
    diag_err_t (*forcestop)(diag_obj_t *diag);
    diag_err_t (*clearstatis)(diag_obj_t *diag);
} diag_ops_t;

struct diag_obj_s {
    diag_mode_t     mode;
    diag_state_t    state;
    diag_err_t      err;
    pthread_mutex_t mutex;
    pthread_t       task;

    diag_cfg_t      cfg;
    diag_stat_t     stat;

    diag_ops_t      ops;
};

#define op_start        ops.start
#define op_stop         ops.stop
#define op_forcestop    ops.forcestop
#define op_clearstatis  ops.clearstatis

#endif /* __DIAG_INTER_H__ */
