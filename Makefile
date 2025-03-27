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
KERNEL_OBJS = $(KERNEL_DIR)/boot.o \
              $(KERNEL_DIR)/kernel.o \
              $(KERNEL_DIR)/interrupt.o \
              $(KERNEL_DIR)/gdt.o \
              $(KERNEL_DIR)/idt.o \
              $(KERNEL_DIR)/io.o \
              $(KERNEL_DIR)/keyboard.o \
              $(KERNEL_DIR)/terminal.o \
              $(KERNEL_DIR)/line.o \
              $(KERNEL_DIR)/memory.o \
              $(KERNEL_DIR)/paging.o \
              $(KERNEL_DIR)/kmalloc.o \
              $(KERNEL_DIR)/process.o \
              $(KERNEL_DIR)/scheduler.o \
              $(KERNEL_DIR)/syscall.o \
              $(KERNEL_DIR)/fs.o \
              $(KERNEL_DIR)/elf.o \
              $(KERNEL_DIR)/dynamic.o

# Targets
all: kernel initrd

kernel: $(KERNEL_OBJS)
	$(CC) $(CFLAGS) -c $(KERNEL_DIR)/kernel.c -o $(KERNEL_DIR)/kernel.o
	$(LD) $(LDFLAGS) -o kernel.bin $(KERNEL_OBJS)
	cat $(BOOT_DIR)/boot.bin kernel.bin > os.img
	rm kernel.bin

initrd:
	$(TOOLS_DIR)/build_initrd.sh

clean:
	rm -f $(KERNEL_OBJS) os.img
	rm -f $(BOOT_DIR)/initrd.img

.PHONY: all kernel initrd clean 