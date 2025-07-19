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

bin_PROGRAMS = Sub64 Selfhealutil RxTx100

Sub64_SOURCES = sub64.c
Sub64_CPPFLAGS = -I$(top_srcdir)/source -I$(top_srcdir)/source/util

Selfhealutil_SOURCES = selfheal_utility.c
Selfhealutil_CPPFLAGS =
Selfhealutil_LDFLAGS =
if ENABLE_MTA
Selfhealutil_CPPFLAGS += -DENABLE_MTA
Selfhealutil_LDFLAGS += -lhal_mta
endif

RxTx100_SOURCES = rxtx_100.c
RxTx100_CPPFLAGS = -I$(top_srcdir)/source -I$(top_srcdir)/source/util
RxTx100_LDFLAGS = -lsyscfg -lsecure_wrapper -ltelemetry_msgsender -lhal_platform
if CORE_NET_LIB_FEATURE_SUPPORT
RxTx100_LDFLAGS += -lnet
endif
