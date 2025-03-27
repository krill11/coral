#include "syscall.h"
#include "../proc/process.h"
#include "../fs/fs.h"
#include "../fs/dynamic.h"
#include "../mm/memory.h"
#include "../drivers/terminal.h"
#include <string.h>

// System call handlers
static int sys_fork(struct process* proc, uint32_t* args) {
    struct process* child = process_create(proc->name);
    if (!child) return -1;
    
    // Copy address space
    if (memory_copy_address_space(proc, child) < 0) {
        process_destroy(child);
        return -1;
    }
    
    // Set up child process
    child->parent = proc;
    child->state = PROC_READY;
    child->regs = proc->regs;
    child->regs.eax = 0;  // Child returns 0
    
    // Set up parent process
    proc->regs.eax = child->pid;  // Parent returns child PID
    
    return 0;
}

static int sys_execve(struct process* proc, uint32_t* args) {
    const char* path = (const char*)args[0];
    char** argv = (char**)args[1];
    char** envp = (char**)args[2];
    
    // Load executable
    void* entry_point;
    if (fs_executable_load(path, &entry_point) < 0) {
        return -1;
    }
    
    // Set up new stack with arguments
    uint32_t* new_stack = (uint32_t*)((char*)proc->stack + proc->stack_size - 4096);
    
    // Push environment variables
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            *new_stack-- = (uint32_t)envp[i];
        }
    }
    *new_stack-- = 0;  // NULL terminator
    
    // Push arguments
    if (argv) {
        for (int i = 0; argv[i]; i++) {
            *new_stack-- = (uint32_t)argv[i];
        }
    }
    *new_stack-- = 0;  // NULL terminator
    
    // Push argument count
    *new_stack-- = (uint32_t)(argv ? argv[0] : 0);
    
    // Update stack pointer
    proc->regs.esp = (uint32_t)new_stack;
    
    // Set entry point
    proc->regs.eip = (uint32_t)entry_point;
    
    return 0;
}

static int sys_waitpid(struct process* proc, uint32_t* args) {
    pid_t pid = (pid_t)args[0];
    int* status = (int*)args[1];
    int options = (int)args[2];
    
    struct process* child = process_find(pid);
    if (!child || child->parent != proc) {
        return -1;
    }
    
    // Wait for child to exit
    while (child->state != PROC_ZOMBIE) {
        process_yield();
    }
    
    // Get exit status
    if (status) {
        *status = child->exit_status;
    }
    
    // Clean up child process
    process_destroy(child);
    
    return pid;
}

static int sys_pipe(struct process* proc, uint32_t* args) {
    int* pipefd = (int*)args[0];
    
    // Create pipe
    struct pipe* pipe = pipe_create();
    if (!pipe) return -1;
    
    // Allocate file descriptors
    int read_fd = process_alloc_fd(proc);
    int write_fd = process_alloc_fd(proc);
    
    if (read_fd < 0 || write_fd < 0) {
        pipe_destroy(pipe);
        return -1;
    }
    
    // Set up file descriptors
    proc->files[read_fd] = pipe->read;
    proc->files[write_fd] = pipe->write;
    
    pipefd[0] = read_fd;
    pipefd[1] = write_fd;
    
    return 0;
}

static int sys_dup2(struct process* proc, uint32_t* args) {
    int oldfd = (int)args[0];
    int newfd = (int)args[1];
    
    if (oldfd < 0 || oldfd >= MAX_FILES || newfd < 0 || newfd >= MAX_FILES) {
        return -1;
    }
    
    // Close newfd if it's open
    if (proc->files[newfd]) {
        fs_close(proc->files[newfd]);
    }
    
    // Duplicate file descriptor
    proc->files[newfd] = proc->files[oldfd];
    if (proc->files[newfd]) {
        proc->files[newfd]->refcount++;
    }
    
    return newfd;
}

static int sys_chdir(struct process* proc, uint32_t* args) {
    const char* path = (const char*)args[0];
    
    struct inode* dir = fs_path_to_inode(path, 0);
    if (!dir || !(dir->flags & FF_DIRECTORY)) {
        return -1;
    }
    
    proc->cwd = dir;
    return 0;
}

static int sys_getcwd(struct process* proc, uint32_t* args) {
    char* buf = (char*)args[0];
    size_t size = (size_t)args[1];
    
    if (!buf || size < 2) return -1;
    
    // Get current working directory path
    char path[MAX_PATH];
    if (fs_inode_to_path(proc->cwd, path, sizeof(path)) < 0) {
        return -1;
    }
    
    // Copy to user buffer
    if (strlen(path) >= size) return -1;
    strcpy(buf, path);
    
    return 0;
}

static int sys_ioctl(struct process* proc, uint32_t* args) {
    int fd = (int)args[0];
    int request = (int)args[1];
    void* arg = (void*)args[2];
    
    if (fd < 0 || fd >= MAX_FILES || !proc->files[fd]) {
        return -1;
    }
    
    struct file* file = proc->files[fd];
    
    // Handle terminal-specific ioctls
    if (file->type == FT_TERMINAL) {
        switch (request) {
            case TIOCGETP:
            case TIOCSETP:
            case TIOCSETN:
            case TIOCSETD:
            case TIOCSCTTY:
                return terminal_ioctl(request, arg);
            default:
                return -1;
        }
    }
    
    return -1;
}

static int sys_fcntl(struct process* proc, uint32_t* args) {
    int fd = (int)args[0];
    int cmd = (int)args[1];
    int arg = (int)args[2];
    
    if (fd < 0 || fd >= MAX_FILES || !proc->files[fd]) {
        return -1;
    }
    
    struct file* file = proc->files[fd];
    
    switch (cmd) {
        case F_DUPFD:
            return sys_dup2(proc, (uint32_t[]){fd, arg});
        case F_GETFD:
            return file->flags & FF_CLOEXEC ? 1 : 0;
        case F_SETFD:
            if (arg & 1) {
                file->flags |= FF_CLOEXEC;
            } else {
                file->flags &= ~FF_CLOEXEC;
            }
            return 0;
        case F_GETFL:
            return file->flags;
        case F_SETFL:
            file->flags = (file->flags & ~FF_APPEND) | (arg & FF_APPEND);
            return 0;
        default:
            return -1;
    }
}

// System call table
static int (*syscall_table[])(struct process*, uint32_t*) = {
    [SYS_fork] = sys_fork,
    [SYS_execve] = sys_execve,
    [SYS_waitpid] = sys_waitpid,
    [SYS_pipe] = sys_pipe,
    [SYS_dup2] = sys_dup2,
    [SYS_chdir] = sys_chdir,
    [SYS_getcwd] = sys_getcwd,
    [SYS_ioctl] = sys_ioctl,
    [SYS_fcntl] = sys_fcntl,
};

// Handle system call
int syscall_handle(struct process* proc, uint32_t syscall, uint32_t* args) {
    if (syscall >= sizeof(syscall_table) / sizeof(syscall_table[0])) {
        return -1;
    }
    
    if (!syscall_table[syscall]) {
        return -1;
    }
    
    return syscall_table[syscall](proc, args);
} 