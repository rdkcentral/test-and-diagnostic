##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
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

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -fPIC -fno-exceptions -Os -Wall -Wextra

AM_CPPFLAGS = -Wall -g -Werror
AM_CXXFLAGS = -std=c++17 -lstdc++fs
#AM_CXXFLAGS += --coverage

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

bin_PROGRAMS = CcspTandD_Dml_Test_gtest.bin
CcspTandD_Dml_Test_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest \
                                  -I${top_srcdir}/gtest/include \
                                  -I${top_srcdir}/source \
                                  -I${top_srcdir}/source/include \
                                  -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/dbus-1.0 \
                                  -I$(PKG_CONFIG_SYSROOT_DIR)$(libdir)/dbus-1.0/include \
                                  -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/ccsp \
                                  -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus \
                                  -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/libsafec \
                                  -I${PKG_CONFIG_SYSROOT_DIR}$(includedir) \
                                  -I$(top_srcdir)/source/diagnostic/include \
                                  -I$(top_srcdir)/source/diagnostic/BbhmDiagIpPing \
                                  -I$(top_srcdir)/source/dmltad \
                                  -I$(top_srcdir)/source/TandDSsp \
                                  -I$(top_srcdir)/source/xle_selfheal \
                                  -DCORE_NET_LIB \
                                  -DUNIT_TEST_DOCKER_SUPPORT 
CcspTandD_Dml_Test_gtest_bin_SOURCES = CcspTandD_IP_DmlTest.cpp \
                                  CcspTandD_DNS_DmlTest.cpp  \
                                  CcspTandDSelfhealDmlTest.cpp  \
                                  WanConnectivityCheckTest.cpp \
                                  CosaTandD_Logbackup_DmlTest.cpp \
                                  CcspTandD_Dml_Mock.cpp \
                                  CcspTandD_PowerMGT_DmlTest.cpp \
                                  CcspTandD_Thermal_DmlTest.cpp \
                                  CcspTandD_HWST_DmlTest.cpp \
                                  CcspTandD_XLE_SelfHeal.cpp \
                                  gtest_main.cpp \
                                  $(top_builddir)/source/dmltad/cosa_diagnostic_apis_priv.c \
                                  $(top_builddir)/source/dmltad/cosa_apis_util.c \
                                  $(top_builddir)/source/dmltad/plugin_main.c \
                                  $(top_builddir)/source/dmltad/cosa_diagnostic_apis.c \
                                  $(top_builddir)/source/dmltad/cosa_apis_util_priv.c \
                                  $(top_builddir)/source/dmltad/cosa_ip_dml_priv.c \
                                  $(top_builddir)/source/dmltad/cosa_apis_busutil.c \
                                  $(top_builddir)/source/dmltad/cosa_dns_dml.c \
                                  $(top_builddir)/source/dmltad/plugin_main_apis.c \
                                  $(top_builddir)/source/dmltad/cosa_apis_vendorlogfile.c \
                                  $(top_builddir)/source/dmltad/cosa_deviceinfo_util_priv.c \
                                  $(top_builddir)/source/dmltad/cosa_ip_dml.c \
                                  $(top_builddir)/source/dmltad/diag.c \
                                  $(top_builddir)/source/dmltad/diag_ping.c \
                                  $(top_builddir)/source/dmltad/diag_traceroute.c \
                                  $(top_builddir)/source/dmltad/cosa_selfheal_apis.c \
                                  $(top_builddir)/source/dmltad/cosa_selfheal_dml.c \
                                  $(top_builddir)/source/dmltad/cosa_logbackup_dml.c \
                                  $(top_builddir)/source/dmltad/cosa_logbackup_apis.c \
                                  $(top_builddir)/source/dmltad/cosa_powermgt_tcxb6_dml.c \
                                  $(top_builddir)/source/dmltad/cosa_thermal_dml.c \
                                  $(top_builddir)/source/dmltad/cosa_hwst_dml.c \
                                  $(top_builddir)/source/dmltad/cosa_wanconnectivity_utils.c \
                                  $(top_builddir)/source/dmltad/cosa_wanconnectivity_rbus_handler_apis.c \
                                  $(top_builddir)/source/dmltad/cosa_wanconnectivity_rbus_apis.c \
                                  $(top_builddir)/source/dmltad/cosa_wanconnectivity_operations.c \
                                  $(top_builddir)/source/dmltad/cosa_wanconnectivity_apis.c \
                                  $(top_builddir)/source/xle_selfheal/xle_selfheal_util.c \
                                  $(top_builddir)/source/xle_selfheal/xle_reliability_monitoring.c
CcspTandD_Dml_Test_gtest_bin_LDADD = $(HOME)/usr/local/lib/libmock_ccsp_common.la \
                                  $(HOME)/usr/local/lib/libmock_rbus.la \
                                  $(HOME)/usr/local/lib/libmock_rdklogger.la \
                                  $(HOME)/usr/local/lib/libmock_util.la \
                                  $(HOME)/usr/local/lib/libmock_syscfg.la \
                                  $(HOME)/usr/local/lib/libmock_sysevent.la \
                                  $(HOME)/usr/local/lib/libmock_safec_lib.la \
                                  $(HOME)/usr/local/lib/libmock_utopia.la \
                                  $(HOME)/usr/local/lib/libmock_telemetry.la \
                                  $(HOME)/usr/local/lib/libmock_secure_wrapper.la \
                                  $(HOME)/usr/local/lib/libmock_libev.la \
                                  $(HOME)/usr/local/lib/libmock_pcap.la \
                                  $(HOME)/usr/local/lib/libmock_resolv.la \
                                  $(HOME)/usr/local/lib/libmock_psm.la \
                                  $(HOME)/usr/local/lib/libmock_file_io.la \
                                  $(HOME)/usr/local/lib/libmock_libnet.la
CcspTandD_Dml_Test_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -lpthread

AM_CFLAGS += -fprofile-arcs -ftest-coverage
AM_CXXFLAGS += -fprofile-arcs -ftest-coverage
CcspTandD_Dml_Test_gtest_bin_LDFLAGS += --coverage
