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

#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[])

{
    unsigned long long ns1 = 0;
    unsigned long long ns2 = 0;
    unsigned long long result = 0;
    

    if (1 >= argc) {
        return 0;
    }
   
    ns1 = strtoll(argv[1], (char **)NULL, 10);
    //printf("%llu\n", ns1);
    
    ns2 = strtoll(argv[2], (char **)NULL, 10);
    //printf("%llu\n", ns2);
    
    result = ns1 - ns2;
    printf("%llu\n", result);
    
    //sprintf(cmd,"echo %llu > /var/tmp/logrxtx.txt \n",result);
    //system(cmd); 
    
    return 0;

}
