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

bin_PROGRAMS = ImageHealthChecker

ImageHealthChecker_SOURCES = ImagehealthChecker.c  ImagehealthChecker.h IHC_Client.c  ImageHealthChecker_bus_connection.h ImageHealthChecker_bus_connection.c
ImageHealthChecker_CFLAGS = -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus $(DBUS_CFLAGS)
ImageHealthChecker_LDFLAGS = $(DBUS_LIBS)
ImageHealthChecker_LDFLAGS += -lccsp_common -lpthread -lsyscfg -lrbus -lsecure_wrapper -ltelemetry_msgsender -lprivilege -lhal_ethsw
