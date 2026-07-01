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

# ebpf/Makefile.am — autotools build for eBPF RTT measurement POC
#
# Two build products:
#   tcp_hello.bpf.o  — BPF object:  clang -target bpf  (NOT the cross-compiler)
#   tcp_loader       — ARM binary:   Yocto cross-compiler $(CC)
#
# Non-standard variables — passed in at build time:
#   CLANG        clang binary from clang-native sysroot
#   KERNEL_SRC   kernel source tree root (for include/uapi headers)
#   LIBBPF_INC   libbpf include directory
#   LIBBPF_LIB   libbpf library directory
#
# In Yocto: supply via EXTRA_OEMAKE in the .bbappend.
# Manually:  make CLANG=... KERNEL_SRC=... LIBBPF_INC=... LIBBPF_LIB=...

CLANG      ?= clang
KERNEL_SRC ?=
LIBBPF_INC ?=
LIBBPF_LIB ?=

# Install destination for both products
ebpfdir = $(bindir)/ebpf

EXTRA_DIST = tcp_hello.bpf.c tcp_loader.c

# Build both products only when prerequisites are supplied.
# Standalone builds (README procedure) that lack clang-native or libbpf
# will print a warning and skip gracefully instead of failing.
all-local:
	@if [ -n "$(LIBBPF_INC)" ] && [ -n "$(LIBBPF_LIB)" ]; then \
	    echo "  CC       tcp_loader"; \
	    $(CC) -Wall -O2 $(CPPFLAGS) $(CFLAGS) -I$(LIBBPF_INC) $(srcdir)/tcp_loader.c \
	        $(LDFLAGS) -L$(LIBBPF_LIB) -lbpf -lelf -lz -lpthread -o tcp_loader; \
	else \
	    echo "WARNING: LIBBPF_INC/LIBBPF_LIB not set — skipping tcp_loader build"; \
	fi
	@if [ -n "$(CLANG)" ] && [ -n "$(KERNEL_SRC)" ] && [ -n "$(LIBBPF_INC)" ]; then \
	    echo "  CLANG    tcp_hello.bpf.o"; \
	    $(CLANG) -O2 -target bpf \
	        -I$(KERNEL_SRC)/include/uapi \
	        -I$(KERNEL_SRC)/include \
	        -I$(LIBBPF_INC) \
	        -c $(srcdir)/tcp_hello.bpf.c -o tcp_hello.bpf.o; \
	else \
	    echo "WARNING: CLANG/KERNEL_SRC/LIBBPF_INC not set — skipping BPF object build"; \
	fi

install-exec-local:
	@if [ -f tcp_loader ]; then \
	    $(INSTALL) -d $(DESTDIR)$(ebpfdir); \
	    $(INSTALL) -m 0755 tcp_loader $(DESTDIR)$(ebpfdir)/tcp_loader; \
	fi

install-data-local:
	@if [ -f tcp_hello.bpf.o ]; then \
	    $(INSTALL) -d $(DESTDIR)$(ebpfdir); \
	    $(INSTALL) -m 0644 tcp_hello.bpf.o $(DESTDIR)$(ebpfdir)/tcp_hello.bpf.o; \
	fi

clean-local:
	rm -f tcp_loader tcp_hello.bpf.o
