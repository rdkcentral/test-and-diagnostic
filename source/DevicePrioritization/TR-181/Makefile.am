##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2017 RDK Management
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
######################################################################

ACLOCAL_AMFLAGS = -I m4

noinst_LTLIBRARIES = libDevicePrio.la

libDevicePrio_la_CPPFLAGS = -I$(top_srcdir)/source/DevicePrioritization/ \ 
                            -I$(top_srcdir)/source/DevicePrioritization/TR-181 \
                            -I$(top_srcdir)/source/TandDSsp \
                            -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus 

libDevicePrio_la_SOURCES = device_prio_util_apis.c device_prio_apis.c device_prio_dml.c device_prio_rbus_handler_apis.c

libDevicePrio_la_LDFLAGS = -lccsp_common -lsyscfg -lrbus -lsysevent

libDevicePrio_la_CFLAGS = $(DEVICE_PRIORITIZATION_CFLAGS)

if FEATURE_RDK_SCHEDULER
libDevicePrio_la_SOURCES += webconfig_scheduler_doc.c webconfig_helper_apis.c device_prio_scheduler_apis.c device_prio_webconfig_apis.c

libDevicePrio_la_LDFLAGS += -lmsgpackc -lcurl -lwebconfig_framework -ltrower-base64 -lrdk_scheduler -lcimplog

libDevicePrio_la_CFLAGS += $(RDK_SCHEDULER_CFLAGS)
endif
