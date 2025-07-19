/*********************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
******************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#ifdef ENABLE_MTA

#include "mta_hal.h"

static int mtaBatteryGetPowerMode (void)
{
    char value[32] = { 0 };
    ULONG size = 0;

    mta_hal_InitDB();

    if (mta_hal_BatteryGetPowerStatus(value, &size) == 0)
    {
        return (strcmp(value, "Battery") == 0) ? 1 : 0;
    }

    return 0;
}
#endif

int main (int argc, char *argv[])
{
    int powermode_status = 0;

    if (argc < 2)
        return 0;

#ifdef ENABLE_MTA
    if (strcmp(argv[1], "power_mode") == 0)
    {
        powermode_status = mtaBatteryGetPowerMode();
    }
#endif

    return powermode_status;
}
