#include "terminal.h"
#include "keyboard.h"
#include "line.h"
#include "../mm/memory.h"
#include "../proc/process.h"
#include <string.h>

// VGA ports
#define VGA_CRT_INDEX_PORT  0x3D4
#define VGA_CRT_DATA_PORT   0x3D5
#define VGA_MEMORY_BASE     0xB8000

// VGA registers
#define VGA_CRT_CURSOR_HIGH 0x0E
#define VGA_CRT_CURSOR_LOW  0x0F

// Terminal instance
static struct terminal terminal;

// Initialize terminal
int terminal_init(void) {
    // Initialize terminal structure
    terminal.buffer = (uint16_t*)VGA_MEMORY_BASE;
    terminal.cursor_x = 0;
    terminal.cursor_y = 0;
    terminal.color = TERM_WHITE;
    terminal.attr = 0;
    terminal.foreground_group = 0;
    terminal.session = 0;
    
    // Initialize line discipline
    if (line_init() < 0) return -1;
    
    // Clear screen
    terminal_clear();
    
    // Register keyboard callback
    keyboard_register_callback(terminal_handle_input);
    
    return 0;
}

// Write character to terminal
void terminal_putchar(char c) {
    if (c == '\n') {
        terminal.cursor_x = 0;
        terminal.cursor_y++;
        if (terminal.cursor_y >= TERM_HEIGHT) {
            terminal_scroll();
        }
    } else if (c == '\r') {
        terminal.cursor_x = 0;
    } else if (c == '\t') {
        terminal.cursor_x = (terminal.cursor_x + 8) & ~7;
        if (terminal.cursor_x >= TERM_WIDTH) {
            terminal.cursor_x = 0;
            terminal.cursor_y++;
            if (terminal.cursor_y >= TERM_HEIGHT) {
                terminal_scroll();
            }
        }
    } else if (c == '\b') {
        if (terminal.cursor_x > 0) {
            terminal.cursor_x--;
        }
    } else {
        // Write character
        uint16_t attr = (terminal.color & 0x0F) | (terminal.attr << 8);
        terminal.buffer[terminal.cursor_y * TERM_WIDTH + terminal.cursor_x] = (attr << 8) | c;
        
        terminal.cursor_x++;
        if (terminal.cursor_x >= TERM_WIDTH) {
            terminal.cursor_x = 0;
            terminal.cursor_y++;
            if (terminal.cursor_y >= TERM_HEIGHT) {
                terminal_scroll();
            }
        }
    }
    
    // Update cursor position
    terminal_set_cursor(terminal.cursor_x, terminal.cursor_y);
}

// Write string to terminal
void terminal_write(const char* str) {
    while (*str) {
        terminal_putchar(*str++);
    }
}

// Clear terminal
void terminal_clear(void) {
    uint16_t attr = (terminal.color & 0x0F) | (terminal.attr << 8);
    uint16_t blank = (attr << 8) | ' ';
    
    for (int i = 0; i < TERM_WIDTH * TERM_HEIGHT; i++) {
        terminal.buffer[i] = blank;
    }
    
    terminal.cursor_x = 0;
    terminal.cursor_y = 0;
    terminal_set_cursor(0, 0);
}

// Set cursor position
void terminal_set_cursor(uint16_t x, uint16_t y) {
    uint16_t pos = y * TERM_WIDTH + x;
    
    outb(VGA_CRT_CURSOR_HIGH, VGA_CRT_INDEX_PORT);
    outb((pos >> 8) & 0xFF, VGA_CRT_DATA_PORT);
    outb(VGA_CRT_CURSOR_LOW, VGA_CRT_INDEX_PORT);
    outb(pos & 0xFF, VGA_CRT_DATA_PORT);
}

// Set terminal color
void terminal_set_color(uint8_t fg, uint8_t bg) {
    terminal.color = (bg << 4) | (fg & 0x0F);
}

// Scroll terminal
void terminal_scroll(void) {
    // Move lines up
    for (int i = 0; i < (TERM_HEIGHT - 1) * TERM_WIDTH; i++) {
        terminal.buffer[i] = terminal.buffer[i + TERM_WIDTH];
    }
    
    // Clear bottom line
    uint16_t attr = (terminal.color & 0x0F) | (terminal.attr << 8);
    uint16_t blank = (attr << 8) | ' ';
    for (int i = 0; i < TERM_WIDTH; i++) {
        terminal.buffer[(TERM_HEIGHT - 1) * TERM_WIDTH + i] = blank;
    }
    
    terminal.cursor_y--;
}

// Handle keyboard input
void terminal_handle_input(struct keyboard_event* event) {
    if (!event) return;
    
    // Check if terminal has foreground process group
    if (!terminal.foreground_group) return;
    
    // Handle special keys
    if (event->type == KEY_EVENT_PRESS) {
        switch (event->scancode) {
            case KEY_CTRL_C:
                // Send SIGINT to foreground process group
                process_send_signal(terminal.foreground_group->leader, SIGINT, 0);
                break;
            case KEY_CTRL_Z:
                // Send SIGTSTP to foreground process group
                process_send_signal(terminal.foreground_group->leader, SIGTSTP, 0);
                break;
            case KEY_CTRL_D:
                // Send EOF
                line_input(0);
                break;
        }
    }
    
    // Handle regular input
    if (event->type == KEY_EVENT_PRESS && event->ascii) {
        line_input(event->ascii);
    }
}

// Set foreground process group
void terminal_set_foreground_group(struct terminal* term, struct process_group* group) {
    if (!term) return;
    
    // Remove old foreground group
    if (term->foreground_group) {
        term->foreground_group->flags &= ~PGRP_FOREGROUND;
    }
    
    // Set new foreground group
    term->foreground_group = group;
    if (group) {
        group->flags |= PGRP_FOREGROUND;
    }
}

// Set terminal session
void terminal_set_session(struct terminal* term, struct process_group* session) {
    if (!term) return;
    
    // Remove old session
    if (term->session) {
        // TODO: Handle session cleanup
    }
    
    // Set new session
    term->session = session;
}

// Read from terminal
int terminal_read(struct terminal* term, char* buf, size_t size) {
    if (!term || !buf || size == 0) return -1;
    
    return line_read(buf, size);
}

// Write raw string to terminal
void terminal_write_raw(struct terminal* term, const char* str, size_t size) {
    if (!term || !str) return;
    
    line_write(str, size);
}

// Handle terminal ioctl
int terminal_ioctl(int request, void* arg) {
    switch (request) {
        case TIOCGETP:
            // Get terminal parameters
            if (!arg) return -1;
            return line_get_params((struct termios*)arg);
            
        case TIOCSETP:
            // Set terminal parameters
            if (!arg) return -1;
            return line_set_params((const struct termios*)arg);
            
        case TIOCSETN:
            // Set terminal parameters without waiting
            if (!arg) return -1;
            return line_set_params((const struct termios*)arg);
            
        case TIOCSETD:
            // Set terminal line discipline
            if (!arg) return -1;
            // TODO: Implement line discipline switching
            return 0;
            
        case TIOCSCTTY:
            // Set controlling terminal
            if (!arg) return -1;
            struct process* proc = (struct process*)arg;
            if (!proc || !proc->group) return -1;
            
            terminal_set_foreground_group(&terminal, proc->group);
            terminal_set_session(&terminal, proc->session);
            return 0;
            
        default:
            return -1;
    }
} 