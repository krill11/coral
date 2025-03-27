#include "line.h"
#include "terminal.h"
#include "../proc/process.h"
#include <string.h>

// Line discipline instance
static struct line_discipline line;

// Initialize line discipline
int line_init(void) {
    // Initialize line discipline structure
    line.buffer = kmalloc(LINE_BUFFER_SIZE);
    if (!line.buffer) return -1;
    
    line.size = 0;
    line.pos = 0;
    line.echo = 1;
    line.raw = 0;
    line.canonical = 1;
    line.termios.c_iflag = ICRNL | IXON;
    line.termios.c_oflag = OPOST | ONLCR;
    line.termios.c_cflag = CS8 | CREAD | HUPCL;
    line.termios.c_lflag = ICANON | ECHO | ECHOE | ECHOK | ECHONL;
    
    return 0;
}

// Handle input character
int line_input(char c) {
    if (!line.buffer) return -1;
    
    // Handle special characters
    if (c == '\r' || c == '\n') {
        if (line.size > 0) {
            line.buffer[line.size++] = '\n';
            if (line.echo) terminal_putchar('\n');
        }
        return 1;  // Line complete
    }
    
    if (c == '\b' || c == 127) {  // Backspace or delete
        if (line.size > 0) {
            line.size--;
            if (line.echo) {
                terminal_putchar('\b');
                terminal_putchar(' ');
                terminal_putchar('\b');
            }
        }
        return 0;
    }
    
    if (c == '\t') {  // Tab
        if (line.size < LINE_BUFFER_SIZE - 1) {
            line.buffer[line.size++] = ' ';
            if (line.echo) terminal_putchar(' ');
        }
        return 0;
    }
    
    // Regular character
    if (line.size < LINE_BUFFER_SIZE - 1) {
        line.buffer[line.size++] = c;
        if (line.echo) terminal_putchar(c);
    }
    
    return 0;
}

// Read from line discipline
int line_read(char* buf, size_t size) {
    if (!buf || size == 0) return -1;
    
    // Wait for complete line in canonical mode
    while (line.canonical && line.size == 0) {
        process_yield();
    }
    
    // Copy data to buffer
    size_t n = line.size;
    if (n > size) n = size;
    memcpy(buf, line.buffer, n);
    
    // Remove processed data
    if (n < line.size) {
        memmove(line.buffer, line.buffer + n, line.size - n);
    }
    line.size -= n;
    
    return n;
}

// Write to line discipline
int line_write(const char* buf, size_t size) {
    if (!buf || size == 0) return -1;
    
    for (size_t i = 0; i < size; i++) {
        char c = buf[i];
        
        // Handle output processing
        if (line.termios.c_oflag & OPOST) {
            if (c == '\n' && (line.termios.c_oflag & ONLCR)) {
                terminal_putchar('\r');
            }
        }
        
        terminal_putchar(c);
    }
    
    return size;
}

// Set line discipline parameters
int line_set_params(const struct termios* termios) {
    if (!termios) return -1;
    
    line.termios = *termios;
    line.echo = (termios->c_lflag & ECHO) != 0;
    line.raw = (termios->c_lflag & ICANON) == 0;
    line.canonical = (termios->c_lflag & ICANON) != 0;
    
    return 0;
}

// Get line discipline parameters
int line_get_params(struct termios* termios) {
    if (!termios) return -1;
    
    *termios = line.termios;
    return 0;
}

// Flush line discipline buffer
void line_flush(void) {
    line.size = 0;
    line.pos = 0;
}

// Clean up line discipline
void line_cleanup(void) {
    if (line.buffer) {
        kfree(line.buffer);
        line.buffer = 0;
    }
} 