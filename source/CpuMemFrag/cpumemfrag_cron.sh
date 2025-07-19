#! /bin/sh
##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

CRONTAB_DIR=/var/spool/cron/crontabs/
CRONTAB_FILE=$CRONTAB_DIRroot
CRONFILE_BK="/tmp/cron_tab$$.txt"

if [ "$1" = "" ]
then
   echo "Time interval passed is null for CPU fragmentation collection"
   exit 0
fi

if [ $1 -lt 1 ] || [ $1 -gt 120 ]
then
   echo "Time interval for CPU fragmentation collection is not in valid range (1-120)"
   exit 0
fi

# 
# Based on the time interval passed create cron pattern
# args: $1 - time interval
#
getCronPattern()
{

 # When time interval is less than 24 hours, then cron should
 # be scheduled for the timeinterval everyday
 if [ $1 -le 23 ]
 then
   count=$1
   starter=0
   final=""
   while [ $starter -lt 23 ]
   do
      starter=`expr $starter + $count`
      if [ $starter -eq 24 ]
      then
          final="0,$final"
      elif [ $starter -lt 24 ]
      then
         if [ "$final" = "" ]
         then
            final=$starter
         else
           final="$final,$starter"
         fi
      fi
   done
   echo "0 $final * * *"
 # When the time interval is more than 24 hours and less than 48 hours
 # then cron schdule happens every day. To avoid complexity in time calculation,
 # scheduling is done for the clock hour based on difference (time - 24) 
 elif [ $1 -gt 23 ] && [ $1 -lt 48 ]
 then
    hours=`expr $1 - 24`
    echo "0 $hours * * *"
 # When the time interval is more than 48 hours and less than 72 hours
 # then cron schdule happens every alternate days, To avoid complexity in time calculation,
 # if scheduling happens on odd day of week then cron is scheduled for all odd days 
 elif [ $1 -ge 48 ] && [ $1 -lt 72 ]
 then
   currentDay=`date +"%u"`
   hours=`expr $1 - 48`
   rem=$(( $currentDay % 2 ))
    if [ $rem -eq 0 ]
    then
       echo "0 $hours * * 2,4,6"
    else
       echo "0 $hours * * 1,3,5,7"
    fi
 # When the time interval is more than 72 hours and less than 96 hours
 # then cron schdule happens based on 3rd day from the day scheduling happens.
 elif [ $1 -ge 72 ] && [ $1 -lt 96 ]
 then
     currentDay=`date +"%u"`
     hours=`expr $1 - 72`
     case $currentDay in
     1) echo "0 $hours * * 4,7"
      ;;
     2) echo "0 $hours * * 1,5"
        ;;
     3) echo "0 $hours * * 2,6"
        ;;
     4) echo "0 $hours * * 3,7"
        ;;
     5) echo "0 $hours * * 1,4"
        ;;
     6) echo "0 $hours * * 2,5"
        ;;
     7) echo "0 $hours * * 3,6"
        ;;
     *) echo "0 $hours * * 3,7"
        ;;
     esac
 # When the time interval is more than 96 hours and less than 120
 # then cron schdule happens on 4th day from the day scheduling happens. 
 elif [ $1 -ge 96 ] && [ $1 -lt 120 ]
 then
     currentDay=`date +"%u"`
     hours=`expr $1 - 96`
     if [ $currentDay -le 3 ]
     then
        daySched=`expr $currentDay + 4`
     else
        daySched=`expr $currentDay - 3`
     fi
     echo "0 $hours * * $daySched"
 # When the time interval is 120 then scheduling happens exactly after
 # 120 hours
 elif [ $1 -eq 120 ]
 then
   currentDay=`date +"%u"`
   hours=`date +"%H"`
   if [ $currentDay -le 2 ]
   then
      daySched=`expr $currentDay + 5`
   else
      daySched=`expr $currentDay - 2`
   fi
   echo "0 $hours * * $daySched"
 fi
}

cronPattern=`getCronPattern $1`
echo "Pattern: $cronPattern"

# Reconfigure crontab as per the new interval/pattern
crontab -l -c $CRONTAB_DIR > $CRONFILE_BK
sed -i '/log_buddyinfo.sh/d' $CRONFILE_BK
echo "$cronPattern /usr/ccsp/tad/log_buddyinfo.sh" >> $CRONFILE_BK
crontab $CRONFILE_BK -c $CRONTAB_DIR
rm -rf $CRONFILE_BK
exit 0
