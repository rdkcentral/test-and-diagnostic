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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <stdbool.h>
#include "syscfg/syscfg.h"
#include "current_time.h"

static long long stored_time = -1;
char buf[MAX_BUF_SIZE] = {'\0'};
time_t timeoffset_ethwan_enable = 0;
time_t build_epoch = 0;
time_t currentEpochTime = 0;
time_t epoch_time;
bool updateSystemTimeNeeded = false;
bool updated_system_time = false;

bool IsEthWanEnabled (void)
{
    if (access( "/nvram/ETHWAN_ENABLE" , F_OK ) == 0)
    {
        char buf[8];

        if (syscfg_get(NULL, "eth_wan_enabled", buf, sizeof(buf)) == 0)
        {
            if (strcmp(buf, "true") == 0)
            {
                return true;
            }
        }
    }

    return false;
}

// Function to get current epoch time
time_t getEpochTime() {
    return time(NULL);
}

time_t convert_to_epoch(const char *date_str) 
{
	struct tm timeinfo = {0};
	// Parse the date string manually
	sscanf(date_str, "%d-%d-%d %d:%d:%d",
           &timeinfo.tm_year, &timeinfo.tm_mon, &timeinfo.tm_mday,
           &timeinfo.tm_hour, &timeinfo.tm_min, &timeinfo.tm_sec);
	// Adjust month and year values (January is 0, years since 1900)
	timeinfo.tm_mon -= 1;
	timeinfo.tm_year -= 1900;
	// Use mktime to convert struct tm to epoch time
	return mktime(&timeinfo);
}

//Function to get build time
time_t getBuildEpoch(const char *file_path) 
{
    FILE *file = fopen(file_path, "r");

    if (file == NULL) 
    {
        CcspTraceError(("Error opening file\n"));
	return -1;
    }

    char build_time_str[128];
    const char *search_string = "BUILD_TIME=";

    // Search for the line containing "BUILD_TIME="
    while (fgets(build_time_str, sizeof(build_time_str), file) != NULL) 
    {
        if (strstr(build_time_str, search_string) != NULL) 
	{
            // Found the line containing BUILD_TIME=
            break;
        }
    }

    fclose(file);

    // Extract the value after "BUILD_TIME="
    char *build_time_value = strchr(build_time_str, '=');
    if (build_time_value != NULL) 
    {
    	// Move past the '=' character    
	build_time_value++;

        // Removing leading and trailing whitespace
        while (*build_time_value == ' ' || *build_time_value == '\t') 
	{
            build_time_value++;
        }

        size_t len = strlen(build_time_value);
        while (len > 0 && (build_time_value[len - 1] == ' ' || build_time_value[len - 1] == '\t' || build_time_value[len - 1] == '\n')) 
	{
            build_time_value[--len] = '\0';
        }

        // Removing quotes for epoc parsing
        if (build_time_value[0] == '"' && build_time_value[len - 1] == '"') 
	{
            build_time_value[len - 1] = '\0';
            build_time_value++;
        }
	
	epoch_time = convert_to_epoch(build_time_value);
	CcspTraceInfo(("Build Time (Epoch): %ld\n", epoch_time));
    } 
    else 
    {
        CcspTraceError(("Error extracting build time value\n"));
	return -1;
    }
    return epoch_time;
}

bool setSystemTime(time_t desired_epoch_time)
{
    struct timeval new_timeval;
    new_timeval.tv_sec = desired_epoch_time;
    new_timeval.tv_usec = 0;

    if (settimeofday(&new_timeval, NULL) != 0) 
    {
        CcspTraceError(("Error setting system time\n"));
        return false;
    }

    CcspTraceInfo(("System time set successfully.\n"));

    return true;
}

//create /tmp/clock-event when device time is updated
void setClockEventFile() 
{    
    // Check if file already exists
    if (access(CLOCK_EVENT_PATH, F_OK) != -1) 
    {
    	CcspTraceInfo(("File /tmp/clock-event already exists\n"));
    }
    else
    {
    	// Create the file
    	int fileDescriptor = creat(CLOCK_EVENT_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    	if (fileDescriptor != -1) 
    	{
       	close(fileDescriptor);
        	CcspTraceInfo(("File /tmp/clock-event created successfully\n"));
    	} 
    	else 
    	{
        	CcspTraceError(("Failed to create /tmp/clock-event file\n"));
    	}
    }
}

bool updateStoredTime(long long new_time) {
    //update stored time
    snprintf(buf, sizeof(buf), "%lld", (long long)new_time);
    if((syscfg_set_commit(NULL,TIMEOFFSET_VALUE,buf) != 0))
    {
    	CcspTraceError(("syscfg_set failed\n"));
    	return false;
    }	
    //using static variable to update variable whatever is set because this is used later to set system time
    stored_time = new_time;
    CcspTraceInfo(("stored_time value after set is %lld\n",stored_time));
    return true;  
}

long long str_to_int_conv(char *str_value)
{
	int result = atoi(str_value);
	if (result == 0 && str_value[0] != '0') 
	{
        	CcspTraceError(("Conversion failed. Invalid characters or out of range.\n"));
          	return -1;
	}
	return result;
}

//Function to check if device time is greater or build time
void UpdatedeviceTimeorbuildTime(long long currentEpochTime, long long build_epoch)
{
    CcspTraceInfo(("Current Epoch Time: %lld, Build Epoch Time: %lld\n", (long long)currentEpochTime, (long long)build_epoch));
    timeoffset_ethwan_enable = (build_epoch > currentEpochTime) ? build_epoch : currentEpochTime;
    // Store initial timeoffset_ethwan_enable value
    if (updateStoredTime((long long)timeoffset_ethwan_enable))
    {
        CcspTraceInfo(("Set value is %lld\n", stored_time));

        if (stored_time == (long long)build_epoch)
        {
            //set system time as build time
            setSystemTime(stored_time);
            CcspTraceInfo(("System time set to build time: %lld\n", stored_time));
        }
    } 
}

// Function to get sleep_time based on syscfg variable or default value
void get_sleep_time(unsigned int *sleep_time)
{
	// Attempt to get the value from syscfg
    	if ((syscfg_get(NULL, "timeoffset_sleep_time", buf, sizeof(buf))) == 0)
	{
        	*sleep_time = str_to_int_conv(buf);
        	CcspTraceInfo(("The timeoffset_sleep_time value from syscfg is %u.\n", *sleep_time));
    	}
	else
	{
          	//Assifning default value of 3600 as sleep time
        	CcspTraceInfo(("timeoffset_sleep_time not found in syscfg, assigning %d as default value.\n",SLEEP_TIME));
		*sleep_time = SLEEP_TIME;
    	}
}

// Function to update time in the file every hour
void* updateTimeThread(void* arg) 
{
    unsigned int sleep_time;
    pthread_detach(pthread_self());
    CcspTraceInfo(("updateTimeThread_create thread created successfully\n"));
    
    //get build time in epoc value
    build_epoch = getBuildEpoch(BUILD_TIME_PATH);
    
    currentEpochTime = getEpochTime();
    
    if (build_epoch == -1) 
    {
        CcspTraceError(("Failed to get build epoch time.\n"));
    }
    else
    {
    	if((syscfg_get(NULL, TIMEOFFSET_VALUE, buf, sizeof(buf))) != 0)
    	{
          	CcspTraceInfo(("Syscfg.db updating for the first time\n"));
    		UpdatedeviceTimeorbuildTime((long long)currentEpochTime, (long long)build_epoch);
    	}
        else
        {
         	stored_time = str_to_int_conv(buf);
          	if(stored_time != -1)
                {
                  	//checking if stored time is greater than device time and also greater than or equal to build time
          		CcspTraceInfo(("stored_time value for get is %lld\n",stored_time));
          		if(stored_time > (long long)currentEpochTime && stored_time >= (long long)build_epoch)
          		{
                          	//set stored time as system time
          			if(setSystemTime(stored_time))
                                {
          				CcspTraceInfo(("System time set as stored time: %lld after reboot as it is greater\n",stored_time));
                                }
          		}
          		else
          		{
                          	CcspTraceInfo(("Syscfg.db updating after reboot\n"));
                          	//if the above condition is not satisfied then update stored time as build time or current time whichever is higher.
          			UpdatedeviceTimeorbuildTime((long long)currentEpochTime, (long long)build_epoch);
              		}
              	}
        }
    }


    while (1) 
    {	
    	get_sleep_time(&sleep_time);
	//sleep for 3600 seconds
      	CcspTraceInfo(("Sleeping for %u seconds\n", sleep_time));
	sleep(sleep_time);
	
      	// Get the current time in epoch format
    	currentEpochTime = getEpochTime();
	CcspTraceInfo(("Build time in epoc is %lld\n",(long long)build_epoch));
	
	// Print the current epoch time
    	CcspTraceInfo(("Current Epoch Time: %lld\n", (long long)currentEpochTime));	
      
      	if(syscfg_get(NULL, TIMEOFFSET_VALUE, buf, sizeof(buf)) == 0)
	{
		stored_time = str_to_int_conv(buf); 
          	if(stored_time != -1)
                {
          		CcspTraceInfo(("stored_time value for get is %lld\n",stored_time));
                }
	}
        
	if((long long)currentEpochTime < stored_time)
	{
          	CcspTraceInfo(("Device_time < stored_time\n"));
		if(stored_time > (long long)build_epoch)
		{
			CcspTraceInfo(("stored_time > build_epoch\n"));
			//updating stored time as device time
                  	updateSystemTimeNeeded = true; 
		}
		else
		{
			CcspTraceInfo(("stored_time < build_time\n"));
			//update stored time to build time
			if(updateStoredTime(build_epoch))
			{
				//set device time as build time
				updateSystemTimeNeeded = true;
			}
		}
	}
	else
	{
		if((long long)currentEpochTime < (long long)build_epoch)
		{
                  	CcspTraceInfo(("currentEpochTime < build_epoch\n"));
                  	//set build time as stored time
			if(updateStoredTime(build_epoch))
			{
                  		//set build time as device time
				updateSystemTimeNeeded = true;
			}
		}	
		else
                {
                  	CcspTraceInfo(("currentEpochTime > build_epoch\n"));

			//Update device time as stored time
                  	if(updateStoredTime(currentEpochTime))
                        {
                  		CcspTraceInfo(("Current epoch time updated in the database\n"));
                        }
		 }
	}
        
        // Check the flag and call setSystemTime if needed	
        if (updateSystemTimeNeeded) 
        {
        	CcspTraceInfo(("Updating System time\n"));
        	updated_system_time = setSystemTime(stored_time);
        	if (updated_system_time) 
        	{
        		// Create the file /tmp/clock-event
                  	setClockEventFile();
                  	// Reset the flag
   			updateSystemTimeNeeded = false;
        	}
        	else
        	{
        		CcspTraceError(("System time update failed\n"));	
        	}
        }
    }

    return NULL;
}

void updateTimeThread_create()
{
    pthread_t threadId;

    // Create a thread to update time
    if (pthread_create(&threadId, NULL, updateTimeThread, NULL) != 0) 
    {
        CcspTraceError(("Error creating thread\n"));
    }
}
