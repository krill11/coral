#ifndef _KERNEL_DRIVERS_TERMINAL_H
#define _KERNEL_DRIVERS_TERMINAL_H

#include <stdint.h>
#include "../proc/process.h"

// Terminal dimensions
#define TERM_WIDTH  80
#define TERM_HEIGHT 25

// Colors
#define TERM_BLACK   0
#define TERM_BLUE    1
#define TERM_GREEN   2
#define TERM_CYAN    3
#define TERM_RED     4
#define TERM_MAGENTA 5
#define TERM_BROWN   6
#define TERM_WHITE   7
#define TERM_BRIGHT  8

// Attributes
#define TERM_ATTR_BLINK    0x80
#define TERM_ATTR_BOLD     0x08
#define TERM_ATTR_REVERSE  0x70

// Control sequences
#define TERM_ESC    0x1B
#define TERM_CR     0x0D
#define TERM_LF     0x0A
#define TERM_BS     0x08
#define TERM_TAB    0x09
#define TERM_BEL    0x07

// Keyboard event structure
struct keyboard_event {
    uint8_t scancode;
    uint8_t keycode;
    uint8_t flags;
};

// Terminal structure
struct terminal {
    uint16_t* buffer;
    uint16_t cursor_x;
    uint16_t cursor_y;
    uint8_t color;
    uint8_t attr;
    struct process_group* foreground_group;
    struct process_group* session;
};

// Function declarations
int terminal_init(void);
void terminal_putchar(char c);
void putchar(char c);  // Global putchar function
void terminal_write(const char* str);
void terminal_clear(void);
void terminal_set_cursor(uint16_t x, uint16_t y);
void terminal_set_color(uint8_t fg, uint8_t bg);
void terminal_scroll(void);
void terminal_handle_input(struct keyboard_event* event);
void terminal_set_foreground_group(struct terminal* term, struct process_group* group);
void terminal_set_session(struct terminal* term, struct process_group* session);
int terminal_read(struct terminal* term, char* buf, size_t size);
void terminal_write_raw(struct terminal* term, const char* str, size_t size);
int terminal_ioctl(int request, void* arg);

#endif // _KERNEL_DRIVERS_TERMINAL_H 