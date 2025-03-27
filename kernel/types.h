#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stddef.h>

// Standard type definitions
typedef int32_t pid_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint32_t sigset_t;

// Signal value union
typedef union sigval {
    int sival_int;
    void* sival_ptr;
} sigval_t;

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