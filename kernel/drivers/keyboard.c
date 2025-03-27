#include "keyboard.h"
#include "../io/io.h"
#include "../proc/process.h"
#include <string.h>

// Keyboard ports
#define KEYBOARD_DATA_PORT    0x60
#define KEYBOARD_STATUS_PORT  0x64
#define KEYBOARD_COMMAND_PORT 0x64

// Keyboard commands
#define KEYBOARD_CMD_LED      0xED
#define KEYBOARD_CMD_ECHO     0xEE
#define KEYBOARD_CMD_SCANCODE 0xF0
#define KEYBOARD_CMD_RESET    0xFF

// Keyboard status bits
#define KEYBOARD_STATUS_OUTPUT_FULL  0x01
#define KEYBOARD_STATUS_INPUT_FULL   0x02
#define KEYBOARD_STATUS_SYSTEM_FLAG  0x04
#define KEYBOARD_STATUS_CMD_DATA    0x08
#define KEYBOARD_STATUS_LOCKED      0x10
#define KEYBOARD_STATUS_AUX_OUTPUT  0x20
#define KEYBOARD_STATUS_TIMEOUT     0x40
#define KEYBOARD_STATUS_PARITY_ERR  0x80

// Keyboard driver instance
static struct keyboard_driver keyboard;

// ASCII lookup table for scancodes
static const uint8_t ascii_table[128] = {
    0,   27,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0,   'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0,   '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0,   ' '
};

// Shifted ASCII lookup table
static const uint8_t ascii_shift_table[128] = {
    0,   27,  '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b',
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    0,   'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',
    0,   '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,
    '*', 0,   ' '
};

// Initialize keyboard driver
void keyboard_init(void) {
    // Initialize keyboard structure
    memset(&keyboard, 0, sizeof(struct keyboard_driver));
    keyboard.head = 0;
    keyboard.tail = 0;
    keyboard.count = 0;
    keyboard.flags = 0;
    keyboard.callback = 0;
    
    // Reset keyboard
    outb(KEYBOARD_CMD_RESET, KEYBOARD_COMMAND_PORT);
    
    // Wait for keyboard to be ready
    while (inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_INPUT_FULL);
    
    // Set scancode set 2
    outb(0x60, KEYBOARD_COMMAND_PORT);
    while (inb(KEYBOARD_STATUS_PORT) & KEYBOARD_STATUS_INPUT_FULL);
    outb(0x02, KEYBOARD_DATA_PORT);
    
    // Enable keyboard interrupts
    outb(0xAE, KEYBOARD_COMMAND_PORT);
}

// Register keyboard event callback
void keyboard_register_callback(void (*callback)(struct keyboard_event* event)) {
    keyboard.callback = callback;
}

// Read keyboard event
int keyboard_read(struct keyboard_event* event) {
    if (!event || keyboard.count == 0) return -1;
    
    // Get event from buffer
    memcpy(event, &keyboard.buffer[keyboard.tail], sizeof(struct keyboard_event));
    keyboard.tail = (keyboard.tail + 1) % KEYBOARD_BUFFER_SIZE;
    keyboard.count--;
    
    return 0;
}

// Handle keyboard scancode
void keyboard_handle_scancode(uint8_t scancode) {
    struct keyboard_event event;
    
    // Handle special keys
    if (scancode == 0xE0) {
        uint8_t next = inb(KEYBOARD_DATA_PORT);
        keyboard_handle_special(next);
        return;
    }
    
    // Handle key release
    if (scancode & 0x80) {
        scancode &= 0x7F;
        switch (scancode) {
            case KEY_LSHIFT:
            case KEY_RSHIFT:
                keyboard.flags &= ~KEY_FLAG_SHIFT;
                break;
            case KEY_LCTRL:
                keyboard.flags &= ~KEY_FLAG_CTRL;
                break;
            case KEY_LALT:
                keyboard.flags &= ~KEY_FLAG_ALT;
                break;
        }
        return;
    }
    
    // Handle key press
    switch (scancode) {
        case KEY_LSHIFT:
        case KEY_RSHIFT:
            keyboard.flags |= KEY_FLAG_SHIFT;
            break;
        case KEY_LCTRL:
            keyboard.flags |= KEY_FLAG_CTRL;
            break;
        case KEY_LALT:
            keyboard.flags |= KEY_FLAG_ALT;
            break;
        case KEY_CAPSLOCK:
            keyboard.flags ^= KEY_FLAG_CAPS;
            break;
        case KEY_NUMLOCK:
            keyboard.flags ^= KEY_FLAG_NUM;
            break;
        case KEY_SCROLLLOCK:
            keyboard.flags ^= KEY_FLAG_SCROLL;
            break;
        default:
            // Create keyboard event
            event.scancode = scancode;
            event.ascii = keyboard_scancode_to_ascii(scancode);
            event.flags = keyboard.flags;
            
            // Add to buffer if not full
            if (keyboard.count < KEYBOARD_BUFFER_SIZE) {
                keyboard.buffer[keyboard.head] = event;
                keyboard.head = (keyboard.head + 1) % KEYBOARD_BUFFER_SIZE;
                keyboard.count++;
                
                // Call callback if registered
                if (keyboard.callback) {
                    keyboard.callback(&event);
                }
            }
            break;
    }
}

// Handle special keys
void keyboard_handle_special(uint8_t scancode) {
    struct keyboard_event event;
    
    // Create keyboard event for special key
    event.scancode = scancode;
    event.ascii = 0;
    event.flags = keyboard.flags;
    
    // Add to buffer if not full
    if (keyboard.count < KEYBOARD_BUFFER_SIZE) {
        keyboard.buffer[keyboard.head] = event;
        keyboard.head = (keyboard.head + 1) % KEYBOARD_BUFFER_SIZE;
        keyboard.count++;
        
        // Call callback if registered
        if (keyboard.callback) {
            keyboard.callback(&event);
        }
    }
}

// Convert scancode to ASCII
uint8_t keyboard_scancode_to_ascii(uint8_t scancode) {
    if (scancode >= 128) return 0;
    
    // Handle special cases
    switch (scancode) {
        case KEY_ENTER:
            return '\n';
        case KEY_BACKSPACE:
            return '\b';
        case KEY_TAB:
            return '\t';
        case KEY_SPACE:
            return ' ';
        default:
            // Use appropriate lookup table based on shift state
            if (keyboard.flags & KEY_FLAG_SHIFT) {
                return ascii_shift_table[scancode];
            } else {
                return ascii_table[scancode];
            }
    }
} 