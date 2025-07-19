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

noinst_LTLIBRARIES = libLowLatency.la

libLowLatency_la_CPPFLAGS = -I$(top_srcdir)/source/LatencyMeasurement/ \
                            -I$(top_srcdir)/source/LatencyMeasurement/TR-181 \
                            -I${top_srcdir}/source/LatencyMeasurement/ServiceMonitor/include \
                            -I$(top_srcdir)/source/TandDSsp \
                            -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus

libLowLatency_la_SOURCES = lowlatency_util_apis.c lowlatency_apis.c lowlatency_dml.c lowlatency_rbus_handler_apis.c

libLowLatency_la_LDFLAGS = -lccsp_common -lsyscfg -lrbus -lsysevent -lpthread

libLowLatency_DEPENDENCIES = ${top_builddir}/source/LatencyMeasurement/ServiceMonitor/libCcspTandDSsp_ServiceMonitor.la

libLowLatency_LDADD = $(libLowLatency_DEPENDENCIES)
