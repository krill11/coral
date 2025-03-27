# Compiler and flags
CC = gcc
AS = as
LD = ld

CFLAGS = -m32 -fno-pie -ffreestanding -fno-builtin -O2 -Wall -Wextra
ASFLAGS = --32
LDFLAGS = -m elf_i386 -T linker.ld

# Directories
KERNEL_DIR = kernel
BOOT_DIR = boot
INITRD_DIR = initrd
TOOLS_DIR = tools

# Files
KERNEL_OBJS = $(KERNEL_DIR)/kernel.o \
              $(KERNEL_DIR)/mm/memory.o \
              $(KERNEL_DIR)/fs/fs.o \
              $(KERNEL_DIR)/fs/elf.o \
              $(KERNEL_DIR)/fs/dynamic.o \
              $(KERNEL_DIR)/proc/process.o \
              $(KERNEL_DIR)/proc/signal.o \
              $(KERNEL_DIR)/drivers/terminal.o \
              $(KERNEL_DIR)/drivers/line.o \
              $(KERNEL_DIR)/drivers/keyboard.o

# Targets
all: kernel initrd

# Build rules for object files
$(KERNEL_DIR)/%.o: $(KERNEL_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_DIR)/%.o: $(KERNEL_DIR)/%.asm
	$(AS) $(ASFLAGS) -o $@ $<

kernel: $(KERNEL_OBJS)
	$(LD) $(LDFLAGS) -o kernel.bin $(KERNEL_OBJS)
	cat $(BOOT_DIR)/boot.bin kernel.bin > os.img
	rm kernel.bin

initrd:
	$(TOOLS_DIR)/build_initrd.sh

clean:
	rm -f $(KERNEL_OBJS) os.img
	rm -f $(BOOT_DIR)/initrd.img

.PHONY: all kernel initrd clean 