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

# Install both products under $(bindir)/ebpf/
ebpfdir = $(bindir)/ebpf

# tcp_loader — cross-compiled userspace binary
ebpf_PROGRAMS = tcp_loader

tcp_loader_SOURCES  = tcp_loader.c
tcp_loader_CPPFLAGS = -I$(LIBBPF_INC)
tcp_loader_LDFLAGS  = -L$(LIBBPF_LIB) -lbpf -lelf -lz -lpthread

# tcp_hello.bpf.o — BPF object installed as a data file alongside the loader
ebpf_DATA = tcp_hello.bpf.o

# BPF object must be compiled with clang -target bpf, not $(CC)
EXTRA_DIST = tcp_hello.bpf.c

tcp_hello.bpf.o: tcp_hello.bpf.c
	$(CLANG) -O2 -target bpf \
	    -I$(KERNEL_SRC)/include/uapi \
	    -I$(KERNEL_SRC)/include \
	    -I$(LIBBPF_INC) \
	    -c $< -o $@

clean-local:
	rm -f tcp_hello.bpf.o
