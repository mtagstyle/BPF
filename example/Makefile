# include $(BrazilMake.dir)/targets/clean.mk
# include $(BrazilMake.dir)/std-dirs.mk

# brazil.variables += lib.includedirs

SRC_DIR = src
BUILD_DIR = build

SOURCES = $(wildcard $(SRC_DIR)/*.c)
HEADERS = $(wildcard $(SRC_DIR)/*.h)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCES))

ARCH = $(shell uname -m)-unknown-linux-gnu

CC = $(ARCH)-clang
CC = clang

CFLAGS = -O2 -target bpf -g -Wall -Werror -Wno-int-to-void-pointer-cast
CFLAGS += -Ioverride-headers # We need to replace some system headers to avoid x86 ASM getting in
CFLAGS += $(addprefix -I,$(var.lib.includedirs))
CFLAGS += -I/usr/include/x86_64-linux-gnu/

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -target bpf -c $< -o $@

release: $(OBJECTS)
all: release

format:
	$(ARCH)-clang-format --style=file -i $(SOURCES) $(HEADERS)

.PHONY: release install format all
