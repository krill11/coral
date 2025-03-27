#ifndef _KERNEL_PROC_PROCESS_H
#define _KERNEL_PROC_PROCESS_H

#include <stdint.h>
#include "../mm/memory.h"
#include "../fs/fs.h"
#include "signal.h"

// Process states
#define PROC_NEW      0
#define PROC_READY    1
#define PROC_RUNNING  2
#define PROC_BLOCKED  3
#define PROC_ZOMBIE   4

// Process flags
#define PF_FOREGROUND 0x00000001
#define PF_BACKGROUND 0x00000002
#define PF_STOPPED    0x00000004
#define PF_CONTINUED  0x00000008

// Process group flags
#define PGRP_FOREGROUND 0x00000001
#define PGRP_BACKGROUND 0x00000002
#define PGRP_STOPPED    0x00000004

// Process structure
struct process {
    pid_t pid;
    char name[32];
    struct process* parent;
    struct process* next;
    struct process* prev;
    struct process* children;
    struct process* siblings;
    struct process_group* group;
    struct process_group* session;
    uint32_t state;
    uint32_t flags;
    int exit_status;
    struct regs regs;
    void* stack;
    size_t stack_size;
    struct file* files[MAX_FILES];
    struct inode* cwd;
    struct signal_info signals;
};

// Process group structure
struct process_group {
    pid_t pgid;
    struct process* leader;
    struct process_group* next;
    struct process_group* prev;
    struct process_group* session;
    uint32_t flags;
    struct terminal* terminal;
};

// Signal information
struct signal_info {
    struct sigaction actions[32];
    sigset_t blocked;
    sigset_t pending;
    struct siginfo pending_info[32];
};

// Process management functions
void proc_init(void);
struct process* proc_create(const char* name);
void proc_destroy(struct process* proc);
void proc_schedule(void);
struct process* proc_current(void);
void proc_switch(struct process* next);

// Process system calls
int sys_fork(void);
int sys_execve(const char* filename, char* const argv[], char* const envp[]);
int sys_exit(int status);
int sys_waitpid(int pid, int* status, int options);

// File descriptor system calls
int sys_dup(int oldfd);
int sys_dup2(int oldfd, int newfd);
int sys_pipe(int pipefd[2]);

// Working directory system calls
int sys_chdir(const char* path);
char* sys_getcwd(char* buf, size_t size);

// Process information system calls
pid_t sys_getpid(void);
pid_t sys_getppid(void);

// User/group management system calls
int sys_setuid(uid_t uid);
int sys_setgid(gid_t gid);

// Terminal control system calls
int sys_ioctl(int fd, int request, void* arg);

// Interrupt handling
void interrupt_init(void);
void register_interrupt_handler(uint8_t num, void (*handler)(void));

// Function declarations
struct process* process_create(const char* name);
void process_destroy(struct process* proc);
void process_yield(void);
struct process* process_find(pid_t pid);
int process_alloc_fd(struct process* proc);
void process_free_fd(struct process* proc, int fd);
int process_set_group(struct process* proc, struct process_group* group);
int process_set_session(struct process* proc, struct process_group* session);
int process_set_terminal(struct process* proc, struct terminal* terminal);
void process_send_signal(struct process* proc, int signum, struct siginfo* info);
void process_handle_signal(struct process* proc, int signum);
void process_check_signals(struct process* proc);
void process_wait_for_child(struct process* proc);
void process_exit(struct process* proc, int status);
void process_stop(struct process* proc);
void process_continue(struct process* proc);
void process_put_in_foreground(struct process* proc);
void process_put_in_background(struct process* proc);

#endif // _KERNEL_PROC_PROCESS_H 