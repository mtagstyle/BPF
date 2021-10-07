KERNEL_VERSION=5.4.0-86-generic
KHEADERS_DIR=/lib/modules/${KERNEL_VERSION}
INCLUDEDIRS=-I/usr/include/x86_64-linux-gnu
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
CLANG ?= clang
LLC ?= llc
linuxhdrs ?= /usr/src/linux-headers-5.4.0-86

LINUXINCLUDE =  -I$(linuxhdrs)/arch/x86/include/uapi \
                -I$(linuxhdrs)/arch/x86/include/generated/uapi \
                -I$(linuxhdrs)/include/generated/uapi \
                -I$(linuxhdrs)/include/uapi \
                -I$(linuxhdrs)/include

OBJS = src/netstat.o
all: $(OBJS)

$(OBJS): %.o:%.c
	$(CLANG) $(INC_FLAGS) \
	-D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	$(INCLUDEDIRS) \
	$(LINUXINCLUDE) \
	$(EXTRA_CFLAGS) -c $< --target=bpf -o $@