#ifndef _SIGNAL_H
#define _SIGNAL_H

#include <stdint.h>

// Signal numbers
#define SIGHUP     1   // Hangup
#define SIGINT     2   // Interrupt
#define SIGQUIT    3   // Quit
#define SIGILL     4   // Illegal instruction
#define SIGTRAP    5   // Trace/breakpoint trap
#define SIGABRT    6   // Abort
#define SIGBUS     7   // Bus error
#define SIGFPE     8   // Floating point exception
#define SIGKILL    9   // Kill
#define SIGUSR1    10  // User defined signal 1
#define SIGSEGV    11  // Segmentation fault
#define SIGUSR2    12  // User defined signal 2
#define SIGPIPE    13  // Broken pipe
#define SIGALRM    14  // Alarm clock
#define SIGTERM    15  // Termination
#define SIGSTKFLT  16  // Stack fault
#define SIGCHLD    17  // Child status has changed
#define SIGCONT    18  // Continue
#define SIGSTOP    19  // Stop
#define SIGTSTP    20  // Terminal stop
#define SIGTTIN    21  // Background process attempting read
#define SIGTTOU    22  // Background process attempting write
#define SIGURG     23  // Urgent condition on socket
#define SIGXCPU    24  // CPU time limit exceeded
#define SIGXFSZ    25  // File size limit exceeded
#define SIGVTALRM  26  // Virtual alarm clock
#define SIGPROF    27  // Profiling timer expired
#define SIGWINCH   28  // Window size change
#define SIGIO      29  // I/O now possible
#define SIGPWR     30  // Power failure restart
#define SIGSYS     31  // Bad system call

// Signal action flags
#define SA_NOCLDSTOP  0x00000001  // Don't send SIGCHLD when children stop
#define SA_NOCLDWAIT  0x00000002  // Don't create zombie processes
#define SA_SIGINFO    0x00000004  // Invoke signal-catching function with three arguments
#define SA_ONSTACK    0x08000000  // Take signal on signal stack
#define SA_RESTART    0x10000000  // Restart system call on signal return
#define SA_NODEFER    0x40000000  // Don't automatically block the signal when its handler is being executed
#define SA_RESETHAND  0x80000000  // Reset to SIG_DFL on entry to handler

// Signal handler types
typedef void (*sighandler_t)(int);
typedef void (*sigaction_t)(int, void*, void*);

// Signal action structure
struct sigaction {
    union {
        sighandler_t sa_handler;
        sigaction_t sa_sigaction;
    };
    uint32_t sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
};

// Signal set structure
typedef struct {
    uint32_t sig[2];  // 64 signals
} sigset_t;

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
    union sigval si_value;  // Signal value
};

// Signal value union
union sigval {
    int sival_int;
    void* sival_ptr;
};

// Function declarations
int signal_init(void);
int signal_register(int signum, const struct sigaction* act, struct sigaction* oldact);
int signal_send(pid_t pid, int signum);
int signal_send_group(pid_t pgid, int signum);
int signal_block(const sigset_t* set, sigset_t* oldset);
int signal_unblock(const sigset_t* set, sigset_t* oldset);
int signal_set_mask(const sigset_t* set, sigset_t* oldset);
int signal_pending(sigset_t* set);
void signal_handle(void);

#endif // _SIGNAL_H 