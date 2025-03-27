#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stddef.h>

// Standard type definitions
typedef int32_t pid_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;

// Signal types
typedef struct {
    uint32_t sig[2];  // 64 signals
} sigset_t;

// Signal value union
typedef union sigval {
    int sival_int;
    void* sival_ptr;
} sigval_t;

// Signal information structure
struct siginfo {
    int si_signo;     // Signal number
    int si_errno;     // Error number
    int si_code;      // Signal code
    pid_t si_pid;     // Sending process ID
    uid_t si_uid;     // Real user ID of sending process
    void* si_addr;    // Memory location which caused fault
    int si_status;    // Exit value or signal
    int si_band;      // Band event for SIGPOLL
    sigval_t si_value;  // Signal value
};

// Signal action structure
struct sigaction {
    union {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, struct siginfo*, void*);
    };
    uint32_t sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
};

// Signal information structure for process
struct signal_info {
    struct sigaction actions[32];
    sigset_t blocked;
    sigset_t pending;
    struct siginfo pending_info[32];
};

// Maximum number of open files per process
#define MAX_FILES 1024

// Register structure for process context
struct regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t eip;
    uint32_t eflags;
    uint32_t cs;
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;
    uint32_t ss;
};

#endif // _TYPES_H 