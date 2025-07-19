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

EXTRA_DEPENDENCIES = $(top_builddir)/source-arm/dmltad/libdmlarm.la

lib_LTLIBRARIES = libdmltad.la

libdmltad_la_CPPFLAGS = -I$(top_srcdir)/source/diagnostic/include \
                        -I$(top_srcdir)/source/diagnostic/BbhmDiagIpPing \
                        -I$(top_srcdir)/source/dmltad \
                        -I$(top_srcdir)/source/TandDSsp \
                        -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus

libdmltad_la_SOURCES = cosa_apis_util.c plugin_main.c cosa_apis_util_priv.c cosa_ip_dml_priv.c cosa_apis_busutil.c \
                       cosa_dns_dml.c plugin_main_apis.c cosa_apis_vendorlogfile.c cosa_deviceinfo_util_priv.c cosa_ip_dml.c \
                       cosa_diagnostic_apis.c diag.c diag_ping.c diag_traceroute.c cosa_selfheal_apis.c cosa_selfheal_dml.c \
                       cosa_logbackup_dml.c cosa_logbackup_apis.c cosa_powermgt_tcxb6_dml.c cosa_thermal_dml.c cosa_hwst_dml.c \
                       cosa_wanconnectivity_apis.c cosa_wanconnectivity_utils.c cosa_wanconnectivity_operations.c \
                       cosa_wanconnectivity_rbus_handler_apis.c cosa_wanconnectivity_rbus_apis.c cosa_rdktest_dml.c

if FEATURE_WAREHOUSE_DIAGNOSTICS
libdmltad_la_SOURCES += cosa_warehousediag_apis.c cosa_warehousediag_rbus_apis.c cosa_warehousediag_rbus_handler_apis.c
endif

libdmltad_la_DEPENDENCIES = $(EXTRA_DEPENDENCIES)
libdmltad_la_LIBADD = $(libdmltad_la_DEPENDENCIES)
libdmltad_la_LDFLAGS = -lccsp_common -lsyscfg -lsysevent -lsecure_wrapper -lrbus -lresolv -lev -lpcap
