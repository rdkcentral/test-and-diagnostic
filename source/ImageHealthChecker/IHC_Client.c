/*
 * If not stated otherwise in this file or this component's LICENSE file
 * the following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

#include "ImagehealthChecker.h"
void report_t2(char * event,char type,char *val)
{
    if (type == 's')
    {
        if(T2ERROR_SUCCESS != t2_event_s(event, val))
        {
            IHC_PRINT("%s T2 send Failed\n",__FUNCTION__);
        }
    }
    if (type == 'd')
    {
        if(T2ERROR_SUCCESS != t2_event_d(event, atoi(val)))
        {
            IHC_PRINT("%s T2 send Failed\n",__FUNCTION__);
        }
    }
}
int fnd_cli_diff(int old_val,int new_val)
{
    float diff=0.0;
    if(new_val < old_val)
    {
        diff = ((float)new_val / old_val) * 100;
        return (int)diff;
    }
    return -1;
}
