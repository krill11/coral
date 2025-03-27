#ifndef _KERNEL_SYSCALL_SYSCALL_H
#define _KERNEL_SYSCALL_SYSCALL_H

#include <stdint.h>
#include "../proc/process.h"

// System call numbers
#define SYS_fork     2
#define SYS_execve   11
#define SYS_waitpid  7
#define SYS_pipe     42
#define SYS_dup2     63
#define SYS_chdir    12
#define SYS_getcwd   183
#define SYS_ioctl    54
#define SYS_fcntl    55

// File control commands
#define F_DUPFD      0
#define F_GETFD      1
#define F_SETFD      2
#define F_GETFL      3
#define F_SETFL      4

// Terminal ioctl commands
#define TIOCGETP     0x5401
#define TIOCSETP     0x5402
#define TIOCSETN     0x5403
#define TIOCSETD     0x5423
#define TIOCSCTTY    0x540E

// Function declarations
int syscall_handle(struct process* proc, uint32_t syscall, uint32_t* args);

#endif // _KERNEL_SYSCALL_SYSCALL_H 