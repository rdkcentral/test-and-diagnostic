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
#include <errno.h>
#include <string.h>
#include <msgpack.h>
#include <stdarg.h>
#include "webconfig_scheduler_doc.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* None */

/*----------------------------------------------------------------------------*/
/*                            Global Variables                                */
/*----------------------------------------------------------------------------*/
/* None */

/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
int process_scheduler_doc( scheduler_doc_t *sd, int num, ...); 

static int decode_schedule_table(msgpack_object *key, msgpack_object *val, input_t **t, size_t* input_size);
static int decode_actions_table(msgpack_object *key, msgpack_object *val, schedule_info_t **t);
static int process_map(msgpack_object_map *, input_t **t);
static int create_info_actions_table(schedule_info_t *s, size_t count);
/* Return true on match of key->via.str.ptr of size key->via.str.size */
static bool name_match(msgpack_object *key, const char *name);
int process_schedule_info_doc( schedule_info_t *s, msgpack_object_map *map );

input_t* create_schedule_input( size_t action_exec_count );

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/

/* See webconfig_scheduler_doc.h for details. */
scheduler_doc_t* scheduler_doc_convert( const void *buf, size_t len )
{
	return helper_convert( buf, len, sizeof(scheduler_doc_t), PRIO_MAC_SUBDOC, 
                            MSGPACK_OBJECT_MAP, true,
                           (process_fn_t) process_scheduler_doc,
                           (destroy_fn_t) scheduler_doc_destroy );
}

/* See webconfig_scheduler_doc.h for details. */
void scheduler_doc_destroy( scheduler_doc_t *sd )
{
    CcspTraceWarning(("%s: called\n", __FUNCTION__));
	if( NULL != sd )
	{
        if( NULL != sd->scheduler_info )
		{
			freeScheduleInfo(sd->scheduler_info);
            sd->scheduler_info = NULL;
		}
		if( NULL != sd->subdoc_name )
		{
			free( sd->subdoc_name );
		}
		free( sd );
    }
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/

int process_scheduler_doc( scheduler_doc_t *sd, int num, ... )
{
    CcspTraceWarning(("%s: called\n", __FUNCTION__));

    //To access the variable arguments use va_list 
	va_list valist;
	va_start(valist, num);//start of variable argument loop

	msgpack_object *obj = va_arg(valist, msgpack_object *);//each usage of va_arg fn argument iterates by one time
	msgpack_object_map *mapobj = &obj->via.map;

	msgpack_object *obj1 = va_arg(valist, msgpack_object *);
	sd->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

	msgpack_object *obj2 = va_arg(valist, msgpack_object *);
	sd->version = (uint32_t) obj2->via.u64;

	msgpack_object *obj3 = va_arg(valist, msgpack_object *);
	sd->transaction_id = (uint16_t) obj3->via.u64;
	va_end(valist);//End of variable argument loop

	sd->scheduler_info = (schedule_info_t *) malloc( sizeof(schedule_info_t) );
    if( NULL == sd->scheduler_info )
    {
        CcspTraceWarning(("entries count malloc failed\n"));
        return -1;
    }
    memset( sd->scheduler_info, 0, sizeof(schedule_info_t));

    int ret = process_schedule_info_doc(sd->scheduler_info, mapobj);

	if( SCHEDULER_INFO_OK != ret)
	{
		CcspTraceError(("process_schedule_info_doc failed\n"));
        //Handling of empty qos rules
        if (ret == SCHEDULER_INFO_ACTIONS_ERR) {
            CcspTraceWarning(("process_schedule_info_doc empty actions, err:%d\n", SCHEDULER_INFO_ACTIONS_ERR));
            sd->scheduler_info = NULL;
            return 0;
        }
		return -1;
	}

    return 0;
}


/**
 *  Convert the msgpack map into the doc_t structure.
 *
 *  @param s    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_schedule_info_doc( schedule_info_t *s, msgpack_object_map *map )
{
    CcspTraceInfo(("process_schedule_info_doc - MSGPACK_OBJECT_MAP\n"));

    int ret_val = SCHEDULER_INFO_OK;

    msgpack_object_kv *p = map->ptr;
    int size = map->size;
    msgpack_object *key = &p->key;
    msgpack_object *val = &p->val;

    while (size-- > 0)
    {
        if (0 == strncmp(key->via.str.ptr, WEEKLY_SCHEDULE, key->via.str.size))
        {
            CcspTraceInfo(("Found %s\n", WEEKLY_SCHEDULE));
            if (0 != decode_schedule_table(key, val, &s->weekly, &s->weekly_size))
            {
                CcspTraceError(("%s:weekly schedule error\n", __func__));
                ret_val = SCHEDULER_INFO_WEEKLY_ERR;
            }
        }
        else if (0 == strncmp(key->via.str.ptr, ABSOLUTE_SCHEDULE, key->via.str.size))
        {
            CcspTraceInfo(("Found %s\n", ABSOLUTE_SCHEDULE));
            if (0 != decode_schedule_table(key, val, &s->absolute, &s->absolute_size))
            {
                CcspTraceError(("%s:absolute schedule error\n", __func__));
                ret_val = SCHEDULER_INFO_ABSOLUTE_ERR;
            }
        }
        else if (0 == strncmp(key->via.str.ptr, QOS_CLIENT_RULES_ALIAS, key->via.str.size))
        {
            CcspTraceInfo(("Found %s\n", QOS_CLIENT_RULES_ALIAS));
            if (0 != decode_actions_table(key, val, &s))
            {
                CcspTraceError(("%s:decode_actions_table() failed\n", __func__));
                if (s->actions)
                {
                    free(s->actions);
                    s->actions = NULL;
                }
                ret_val = SCHEDULER_INFO_ACTIONS_ERR;
            }
        } else if (0 == strncmp(key->via.str.ptr, TIME_ZONE, key->via.str.size)) {
            char time_zone[64] = {0};
            strncpy(time_zone, val->via.str.ptr, val->via.str.size);
            CcspTraceInfo(("Found %s: %s\n", TIME_ZONE, time_zone));
        }
        else
        {
            CcspTraceError(("%s: ignoring unknown object \n", __func__));
        }
        p++;
        key = &p->key;
        val = &p->val;
    }        
    
    if( 1 & size ) {
    } else {
        errno = HELPERS_OK;
    }
   
    return (0 == size) ? 0 : ret_val;
}

static int decode_schedule_table(msgpack_object *key, msgpack_object *val, input_t **t, size_t* input_size)
{
    (void)key;
    if (val->type == MSGPACK_OBJECT_ARRAY)
    {
        msgpack_object *ptr = val->via.array.ptr;
        int count = val->via.array.size;
        int i;
        input_t *temp = NULL;

        /* An empty list is ok, but an invalid size is an error. */
        if (count == 0)
        {
            return 0;
        }
        else if (count < 0)
        {
            return -1;
        }

        if (ptr->type == MSGPACK_OBJECT_MAP)
        {
            *input_size = count;

            *t = (input_t*) malloc(sizeof(input_t) * count);
            if (*t == NULL) {
                CcspTraceError(("%s: Memory allocation failed.\n", __FUNCTION__));
                return -1;
            }

            for (i = 0; i < count; i++)
            {
                if (0 == process_map(&ptr->via.map, &temp))
                {
                    (*t)[i].time = temp->time;
                    (*t)[i].action_count = temp->action_count;
                    for (int j = 0; j < temp->action_count; j++) {
                        (*t)[i].action_indexes[j] = temp->action_indexes[j];
                    }
                }
                free(temp);
                ptr++;
            }
        }
    }
    return 0;
}

static int decode_actions_table(msgpack_object *key, msgpack_object *val, schedule_info_t **t)
{
    uint32_t i;
    uint32_t count;
    msgpack_object *ptr = val->via.array.ptr;
    (void)key;

    count = val->via.array.size;

    if (0 == count)
    {
        CcspTraceError(("decode_actions_table(): empty action array\n"));
        return -1;
    }

    if (0 != create_info_actions_table(*t, count))
    {
        CcspTraceError(("decode_actions_table(): create_info_actions_table() failed\n"));
        return -2;
    }

    for (i = 0; i < count; i++) {
        (*t)->actions[i] = strndup(ptr->via.str.ptr, ptr->via.str.size);
        if (NULL == (*t)->actions[i]) {
            CcspTraceError(("decode_actions_table(): assigning action strings failed\n"));
            return -1;
        }
        ptr++;
    }

    return 0;
}

static int process_map(msgpack_object_map *map, input_t **t)
{
    uint32_t size = map->size;
    msgpack_object *key = &map->ptr->key;
    msgpack_object *val = &map->ptr->val;
    msgpack_object_kv *kv = map->ptr;
    uint32_t cnt;
    time_t entry_time = 0;
    int ret_val = 0;

    *t = NULL;

    for (cnt = 0; cnt < size; cnt++)
    {
        if (key->type == MSGPACK_OBJECT_STR && val->type == MSGPACK_OBJECT_POSITIVE_INTEGER && (name_match(key, UNIX_TIME_STR) || name_match(key, RELATIVE_TIME_STR)))
        {
            entry_time = val->via.u64;
        }
        else if (key->type == MSGPACK_OBJECT_STR && val->type == MSGPACK_OBJECT_NIL)
        {
            *t = create_schedule_input(0);
        }
        else if (key->type == MSGPACK_OBJECT_STR && val->type == MSGPACK_OBJECT_ARRAY && name_match(key, INDEXES_STR))
        {
            msgpack_object *ptr = val->via.array.ptr;
            uint32_t array_size = 0;

            *t = create_schedule_input(val->via.array.size);

            if (NULL != (*t))
            {
                for (; array_size < (val->via.array.size); array_size++)
                {
                    (*t)->action_indexes[array_size] = ptr->via.u64;
                    CcspTraceInfo(("Array Element[%d] = %d action_index_list[] %d\n",
                                array_size, (uint32_t)ptr->via.u64,
                                (*t)->action_indexes[array_size]));
                    ptr++;
                }
            }
            else
            {
                ret_val = -2;
            }
        }
        else
        {
            CcspTraceError(("Unexpected Item in msgpack_object_map\n"));
            ret_val = -1;
            break;
        }

        kv++;
        key = &kv->key;
        val = &kv->val;
    }

    if (NULL != *t)
    {
        (*t)->time = entry_time;
    }
    return ret_val;
}

input_t* create_schedule_input( size_t action_exec_count )
{
    input_t *s = NULL;
    size_t size;
    //size_t max_actions = get_max_actions_limit(); //TODO
    size_t max_actions = 255;

    if (action_exec_count > max_actions) {
        CcspTraceError(("create_schedule_input() Error Request %d exceeds maximum %d\n",
                     action_exec_count, max_actions));
        return s;
    }

    size = sizeof(input_t) + action_exec_count * sizeof(uint32_t);

    s = (input_t*) malloc( size );
    if( NULL != s ) {
        memset( s, 0, size );
        s->action_count = action_exec_count;
    }

    return s;
}

static int create_info_actions_table(schedule_info_t *s, size_t count)
{
    s->actions = (char **) malloc(count * sizeof(char *));
    if (NULL == s->actions) {
        return -1;
    }
    s->actions_size = count;

    memset(s->actions, 0, count * sizeof(char *));

    return 0;
}

static bool name_match(msgpack_object *key, const char *name)
{
    bool result = (0 == strncmp(key->via.str.ptr, name, key->via.str.size));

    return result;
}
