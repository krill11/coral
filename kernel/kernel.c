#include <stdint.h>
#include "mm/memory.h"
#include "proc/process.h"
#include "fs/fs.h"

// Video memory constants
#define VGA_MEMORY 0xB8000
#define VGA_WIDTH 80
#define VGA_HEIGHT 25

// Colors
#define VGA_BLACK 0
#define VGA_WHITE 15
#define VGA_COLOR(fg, bg) ((bg << 4) | fg)

// Current position in video memory
static uint16_t* video_memory = (uint16_t*)VGA_MEMORY;
static int cursor_x = 0;
static int cursor_y = 0;

// Clear the screen
void clear_screen() {
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        video_memory[i] = VGA_COLOR(VGA_WHITE, VGA_BLACK) << 8 | ' ';
    }
}

// Print a character
void putchar(char c) {
    if (c == '\n') {
        cursor_x = 0;
        cursor_y++;
        return;
    }

    const int index = cursor_y * VGA_WIDTH + cursor_x;
    video_memory[index] = VGA_COLOR(VGA_WHITE, VGA_BLACK) << 8 | c;
    
    cursor_x++;
    if (cursor_x >= VGA_WIDTH) {
        cursor_x = 0;
        cursor_y++;
    }
}

// Print a string
void print(const char* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        putchar(str[i]);
    }
}

// Test process creation
void test_processes() {
    print("Testing process creation...\n");
    
    // Create a test process
    struct process* test_proc = proc_create("test_process");
    if (test_proc) {
        print("Process created successfully!\n");
        print("Process name: ");
        print(test_proc->name);
        print("\n");
        print("Process ID: ");
        // TODO: Add number printing function
        print("\n");
    } else {
        print("Process creation failed!\n");
    }
}

// Kernel entry point
void kernel_main() {
    clear_screen();
    print("CoralOS Kernel Loaded Successfully!\n");
    print("Initializing system...\n");
    
    // Initialize memory management
    mm_init();
    print("Memory management initialized\n");
    
    // Initialize filesystem
    fs_init();
    print("Filesystem initialized\n");
    
    // Initialize process management
    proc_init();
    print("Process management initialized\n");
    
    // Test process creation
    test_processes();
    
    // TODO: Initialize device drivers
    
    while(1) {
        // Kernel main loop
        proc_schedule();
        __asm__ volatile("hlt");
    }
} 