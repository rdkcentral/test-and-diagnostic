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
#   CLANG         clang binary from clang-native sysroot
#   KERNEL_SRC    kernel source tree root (for include/uapi headers)
#   KERNEL_BUILD  kernel build directory  (for include/generated/autoconf.h)
#                 In Yocto: $(STAGING_KERNEL_BUILDDIR)
#   LIBBPF_INC    libbpf include directory
#   LIBBPF_LIB    libbpf library directory
#
# In Yocto: supply via EXTRA_OEMAKE in the .bbappend.
# Manually:  make CLANG=... KERNEL_SRC=... KERNEL_BUILD=... LIBBPF_INC=... LIBBPF_LIB=...

CLANG        ?= clang
KERNEL_SRC   ?=
KERNEL_BUILD ?= $(KERNEL_SRC)
LIBBPF_INC   ?=
LIBBPF_LIB   ?=

# Install destination for both products
ebpfdir = $(bindir)/ebpf

EXTRA_DIST = tcp_rtt.h bpf_net_defs.h skbuff_offset.h tcp_hello.bpf.c tcp_loader.c \
             prebuilt/LICENSE_HEADER prebuilt/tcp_hello_bpf_o.h prebuilt/SHA256SUMS

# Build both products only when prerequisites are supplied.
# Build both products only when prerequisites are supplied.
# Non-fatal: all eBPF build failures are printed as warnings so that the
# broader image compilation always succeeds.
all-local:
	@BPF_OK=0; \
	 \
	 if [ -n "$(CLANG)" ] && [ -x "$(CLANG)" ] && [ -n "$(KERNEL_SRC)" ] && [ -n "$(LIBBPF_INC)" ]; then \
	    CLANG_VER=$$($(CLANG) --version 2>/dev/null | grep -oE 'clang version [0-9]+' | grep -oE '[0-9]+$$'); \
	    if [ -z "$$CLANG_VER" ]; then \
	        echo "[eBPF] WARNING: could not determine clang version — proceeding"; \
	    elif [ "$$CLANG_VER" -lt 10 ]; then \
	        echo "[eBPF] WARNING: clang $$CLANG_VER too old (need >= 10) — skipping compile, trying prebuilt"; \
	        CLANG_VER=skip; \
	    else \
	        echo "[eBPF] clang version $$CLANG_VER OK"; \
	    fi; \
	    if [ "$$CLANG_VER" != "skip" ]; then \
	    echo "[eBPF] CLANG    tcp_hello.bpf.o"; \
	    $(CLANG) -O2 -target bpf \
	        -D__KERNEL__ \
	        -D__TARGET_ARCH_arm \
	        -Wno-deprecated-declarations \
	        $(if $(KERNEL_BUILD),-include $(KERNEL_BUILD)/include/generated/autoconf.h) \
	        -I$(KERNEL_SRC)/include/uapi \
	        -I$(KERNEL_SRC)/arch/arm/include/uapi \
	        -I$(KERNEL_SRC)/include \
	        -I$(KERNEL_SRC)/arch/arm/include \
	        $(if $(KERNEL_BUILD),-I$(KERNEL_BUILD)/arch/arm/include/generated) \
	        -I$(LIBBPF_INC) \
	        -c $(srcdir)/tcp_hello.bpf.c -o tcp_hello.bpf.o; \
	    if [ -f tcp_hello.bpf.o ]; then \
	        echo "[eBPF] EMBED    tcp_hello_bpf_o.h (od)"; \
	        { cat "$(srcdir)/prebuilt/LICENSE_HEADER"; \
	          printf 'static const unsigned char tcp_hello_bpf_o[] = {\n'; \
	          od -v -An -tx1 tcp_hello.bpf.o | awk '{for(i=1;i<=NF;i++) printf "0x%s,", $$i}'; \
	          printf '\n};\nstatic const unsigned int tcp_hello_bpf_o_len = %u;\n' \
	                 "$$(wc -c < tcp_hello.bpf.o)"; \
	        } > tcp_hello_bpf_o.h \
	        && cp tcp_hello_bpf_o.h $(srcdir)/prebuilt/tcp_hello_bpf_o.h \
	        && (cd "$(srcdir)" && sha256sum tcp_hello.bpf.c bpf_net_defs.h \
	                              skbuff_offset.h tcp_rtt.h > prebuilt/SHA256SUMS) \
	        && echo "[eBPF] SHA256SUMS  prebuilt/SHA256SUMS updated" \
	        && rm -f tcp_hello.bpf.o \
	        && BPF_OK=1 \
	        || echo "[eBPF] WARNING:  embed/copy step failed"; \
	    else \
	        echo "[eBPF] WARNING:  BPF compilation failed — trying prebuilt"; \
	    fi; \
	    fi; \
	 elif [ -f "$(srcdir)/prebuilt/tcp_hello_bpf_o.h" ]; then \
	    echo "[eBPF] PREBUILT  tcp_hello_bpf_o.h (clang/KERNEL_SRC not available)"; \
	    if [ -f "$(srcdir)/prebuilt/SHA256SUMS" ]; then \
	        if (cd "$(srcdir)" && sha256sum -c prebuilt/SHA256SUMS --quiet 2>/dev/null); then \
	            echo "[eBPF] VERIFY    prebuilt SHA256SUMS OK — sources unchanged"; \
	        else \
	            echo "[eBPF] WARNING:  prebuilt/SHA256SUMS mismatch — sources changed since last compile"; \
	            echo "[eBPF] WARNING:  rebuild with clang when possible"; \
	        fi; \
	    else \
	        echo "[eBPF] WARNING:  no SHA256SUMS for prebuilt — cannot verify freshness"; \
	    fi; \
	    cp "$(srcdir)/prebuilt/tcp_hello_bpf_o.h" tcp_hello_bpf_o.h && BPF_OK=1; \
	 else \
	    echo "[eBPF] WARNING:  no clang and no prebuilt/tcp_hello_bpf_o.h — skipping eBPF build"; \
	 fi; \
	 \
	 if [ $$BPF_OK -eq 1 ] && [ -n "$(LIBBPF_INC)" ] && [ -n "$(LIBBPF_LIB)" ]; then \
	    echo "[eBPF] CC        tcp_loader"; \
	    $(CC) -Wall -O2 $(CPPFLAGS) $(CFLAGS) -I. -I$(LIBBPF_INC) $(srcdir)/tcp_loader.c \
	        $(LDFLAGS) -L$(LIBBPF_LIB) -lbpf -lelf -lz -lpthread -o tcp_loader \
	    || echo "[eBPF] WARNING:  tcp_loader compilation failed"; \
	 elif [ $$BPF_OK -eq 1 ]; then \
	    echo "[eBPF] WARNING:  LIBBPF_INC/LIBBPF_LIB not set — skipping tcp_loader build"; \
	 else \
	    echo "[eBPF] SKIP      tcp_loader (no BPF object available)"; \
	 fi; true

install-exec-local:
	@if [ -f tcp_loader ]; then \
	    $(INSTALL) -d $(DESTDIR)$(ebpfdir); \
	    $(INSTALL) -m 0755 tcp_loader $(DESTDIR)$(ebpfdir)/tcp_loader; \
	fi

install-data-local:
	@# BPF object is now embedded in tcp_loader — no separate install needed.

clean-local:
	rm -f tcp_loader tcp_hello.bpf.o tcp_hello_bpf_o.h
