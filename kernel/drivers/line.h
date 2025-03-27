#ifndef _KERNEL_DRIVERS_LINE_H
#define _KERNEL_DRIVERS_LINE_H

#include <stdint.h>

// Line discipline buffer size
#define LINE_BUFFER_SIZE 4096

// Terminal I/O flags
#define ICRNL    0x00000100  // Map CR to NL on input
#define IXON     0x00000200  // Enable start/stop output control
#define OPOST    0x00000001  // Post-process output
#define ONLCR    0x00000004  // Map NL to CR-NL on output
#define CS8      0x00000300  // 8-bit characters
#define CREAD    0x00000080  // Enable receiver
#define HUPCL    0x00000400  // Hang up on last close
#define ICANON   0x00000002  // Canonical input
#define ECHO     0x00000008  // Enable echo
#define ECHOE    0x00000010  // Echo ERASE as backspace
#define ECHOK    0x00000020  // Echo KILL
#define ECHONL   0x00000040  // Echo NL

// Terminal I/O structure
struct termios {
    uint32_t c_iflag;  // Input flags
    uint32_t c_oflag;  // Output flags
    uint32_t c_cflag;  // Control flags
    uint32_t c_lflag;  // Local flags
    uint8_t c_cc[32];  // Control characters
};

// Line discipline structure
struct line_discipline {
    char* buffer;
    size_t size;
    size_t pos;
    int echo;
    int raw;
    int canonical;
    struct termios termios;
};

// Function declarations
int line_init(void);
int line_input(char c);
int line_read(char* buf, size_t size);
int line_write(const char* buf, size_t size);
int line_set_params(const struct termios* termios);
int line_get_params(struct termios* termios);
void line_flush(void);
void line_cleanup(void);

#endif // _KERNEL_DRIVERS_LINE_H 