##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2026 RDK Management
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

bin_PROGRAMS = dns_conntrack_failover

dns_conntrack_failover_SOURCES = \
	main.c \
	dns_monitor.c \
	dns_probe.c \
	resolver_list.c \
	failover_config.c \
	wan_status.c \
	dns_redirect.c \
	ip_addr.c
dns_conntrack_failover_LDFLAGS = -lnetfilter_conntrack -lnfnetlink -lpthread

EXTRA_DIST = \
	dns_monitor.h \
	dns_probe.h \
	resolver_list.h \
	failover_config.h \
	wan_status.h \
	dns_redirect.h \
	ip_addr.h
