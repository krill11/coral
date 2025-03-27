#include "process.h"
#include "../fs/fs.h"
#include <stddef.h>
#include <string.h>

// Process list
static struct process* process_list = 0;
static struct process* current_process = 0;
static pid_t next_pid = 1;

// Process group list
static struct process_group* group_list = 0;

// Interrupt handlers
#define MAX_INTERRUPTS 256
static void (*interrupt_handlers[MAX_INTERRUPTS])(void);

// Find process by PID
static struct process* find_process(pid_t pid) {
    struct process* p = process_list;
    while (p) {
        if (p->pid == pid) return p;
        p = p->next;
    }
    return 0;
}

// Copy memory from one process to another
static void copy_process_memory(struct process* dest, struct process* src) {
    // Copy page directory structure
    for (int i = 0; i < 1024; i++) {
        if (src->page_directory[i] & PAGE_PRESENT) {
            // Create new page table for destination
            page_table_t new_table = (page_table_t)get_page();
            if (!new_table) continue;
            
            // Map the new table
            dest->page_directory[i] = (page_t)new_table | PAGE_PRESENT | PAGE_RW | PAGE_USER;
            
            // Get source page table
            page_table_t src_table = (page_table_t)(src->page_directory[i] & PAGE_MASK);
            
            // Copy page table entries
            for (int j = 0; j < 1024; j++) {
                if (src_table[j] & PAGE_PRESENT) {
                    // Allocate new physical page
                    void* new_page = get_page();
                    if (!new_page) continue;
                    
                    // Map the new page
                    new_table[j] = (page_t)new_page | (src_table[j] & 0xFFF);
                    
                    // Copy page contents
                    void* src_addr = (void*)((i << 22) | (j << 12));
                    void* dest_addr = (void*)((i << 22) | (j << 12));
                    
                    // Temporarily map source page to copy
                    uint32_t temp_page = src_table[j];
                    src_table[j] = 0; // Unmap temporarily
                    map_page(new_page, dest_addr, PAGE_PRESENT | PAGE_RW | PAGE_USER);
                    memcpy(dest_addr, src_addr, PAGE_SIZE);
                    src_table[j] = temp_page; // Restore mapping
                } else {
                    new_table[j] = 0;
                }
            }
        } else {
            dest->page_directory[i] = 0;
        }
    }
}

// Initialize process context
static void init_process_context(struct process* proc) {
    // Set up initial stack
    uint32_t* stack = (uint32_t*)((uint32_t)proc + PAGE_SIZE - 16);
    
    // Push initial context
    *(--stack) = 0; // EFLAGS
    *(--stack) = 0x08; // CS (kernel code segment)
    *(--stack) = 0; // EIP (will be set by execve)
    
    // Save stack pointer
    proc->esp = (uint32_t)stack;
    proc->ebp = proc->esp;
}

// Initialize process memory
static int init_process_memory(struct process* proc) {
    // Allocate initial stack
    void* stack = get_page();
    if (!stack) return -1;
    
    // Map stack into process space
    map_page(stack, (void*)((uint32_t)proc + PAGE_SIZE - PAGE_SIZE), 
             PAGE_PRESENT | PAGE_RW | PAGE_USER);
    
    return 0;
}

// Initialize process management
void proc_init(void) {
    // Initialize process list
    process_list = 0;
    current_process = 0;
    next_pid = 1;
    
    // Initialize interrupt handlers
    memset(interrupt_handlers, 0, sizeof(interrupt_handlers));
    
    // Initialize signal handling
    if (signal_init() < 0) {
        // Handle error
        return;
    }
    
    // Initialize keyboard driver
    keyboard_init();
    
    // Initialize terminal driver
    terminal_init();
    
    // Create init process
    struct process* init = proc_create("init");
    if (!init) {
        // Handle error
        return;
    }
    
    // Set up init process
    init->uid = 0;
    init->gid = 0;
    init->pgid = init->pid;
    init->sid = init->pid;
    
    // Set up initial file descriptors
    init->file_descriptors[0] = fs_open("/dev/tty0", O_RDONLY);
    init->file_descriptors[1] = fs_open("/dev/tty0", O_WRONLY);
    init->file_descriptors[2] = fs_open("/dev/tty0", O_WRONLY);
    
    // Set up initial working directory
    strcpy(init->cwd, "/");
    
    // Set up initial process memory and context
    if (init_process_memory(init) < 0) {
        proc_destroy(init);
        return;
    }
    
    init_process_context(init);
    
    // Set current process
    current_process = init;
    
    // Set up initial signal handlers
    struct sigaction act;
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    
    for (int i = 1; i <= MAX_SIGNALS; i++) {
        signal_register(i, &act, 0);
    }
    
    // Set up terminal for init process
    terminal_set_foreground_group(init);
    terminal_set_session(init);
}

// Create a new process
struct process* proc_create(const char* name) {
    struct process* proc = kmalloc(sizeof(struct process));
    if (!proc) return 0;
    
    // Initialize basic fields
    proc->pid = next_pid++;
    proc->parent_pid = current_process ? current_process->pid : 0;
    proc->state = PROC_CREATED;
    proc->exit_status = 0;
    proc->next = 0;
    
    // Copy process name
    strncpy(proc->name, name, sizeof(proc->name) - 1);
    proc->name[sizeof(proc->name) - 1] = 0;
    
    // Create page directory
    proc->page_directory = create_page_directory();
    if (!proc->page_directory) {
        kfree(proc);
        return 0;
    }
    
    // Initialize file descriptors
    proc->file_descriptors = kmalloc(sizeof(int) * MAX_FDS);
    if (!proc->file_descriptors) {
        free_page_directory(proc->page_directory);
        kfree(proc);
        return 0;
    }
    proc->num_fds = MAX_FDS;
    for (int i = 0; i < MAX_FDS; i++) {
        proc->file_descriptors[i] = -1;
    }
    
    // Set working directory
    if (current_process) {
        strncpy(proc->cwd, current_process->cwd, sizeof(proc->cwd) - 1);
    } else {
        strncpy(proc->cwd, "/", sizeof(proc->cwd) - 1);
    }
    proc->cwd[sizeof(proc->cwd) - 1] = 0;
    
    // Set user and group IDs
    proc->uid = current_process ? current_process->uid : 0;
    proc->gid = current_process ? current_process->gid : 0;
    
    // Set process group and session
    proc->pgid = current_process ? current_process->pgid : proc->pid;
    proc->sid = current_process ? current_process->sid : proc->pid;
    
    // Initialize terminal
    proc->tty = current_process ? current_process->tty : 0;
    
    // Initialize signal handling
    memset(proc->signal_handlers, 0, sizeof(proc->signal_handlers));
    memset(&proc->signal_mask, 0, sizeof(sigset_t));
    memset(&proc->pending_signals, 0, sizeof(sigset_t));
    
    // Allocate signal stack
    proc->signal_stack = get_page();
    if (!proc->signal_stack) {
        kfree(proc->file_descriptors);
        free_page_directory(proc->page_directory);
        kfree(proc);
        return 0;
    }
    
    // Add to process list
    proc->next = process_list;
    process_list = proc;
    
    return proc;
}

// Destroy a process
void proc_destroy(struct process* proc) {
    if (!proc) return;
    
    // Remove from process list
    if (process_list == proc) {
        process_list = proc->next;
    } else {
        struct process* p = process_list;
        while (p && p->next != proc) {
            p = p->next;
        }
        if (p) {
            p->next = proc->next;
        }
    }
    
    // Free file descriptors
    for (int i = 0; i < proc->num_fds; i++) {
        if (proc->file_descriptors[i] >= 0) {
            fs_close(proc->file_descriptors[i]);
        }
    }
    kfree(proc->file_descriptors);
    
    // Free page directory
    free_page_directory(proc->page_directory);
    
    // Free signal stack
    if (proc->signal_stack) {
        free_page(proc->signal_stack);
    }
    
    // Free process structure
    kfree(proc);
}

// Get current process
struct process* proc_current(void) {
    return current_process;
}

// Switch to next process
void proc_switch(struct process* next) {
    if (!next || next == current_process) return;
    
    struct process* prev = current_process;
    current_process = next;
    current_process->state = PROC_RUNNING;
    
    if (prev) {
        prev->state = PROC_READY;
    }
    
    // Switch page directory
    __asm__ volatile("movl %0, %%cr3" : : "r"(next->page_directory));
    
    // Restore process context
    __asm__ volatile(
        "movl %0, %%esp\n"
        "movl %1, %%ebp\n"
        "popl %%gs\n"
        "popl %%fs\n"
        "popl %%es\n"
        "popl %%ds\n"
        "popa\n"
        "iret\n"
        : : "r"(next->esp), "r"(next->ebp)
    );
}

// Simple round-robin scheduler
void proc_schedule(void) {
    struct process* next = current_process ? current_process->next : process_list;
    if (!next) next = process_list;
    
    proc_switch(next);
}

// Initialize interrupt handling
void interrupt_init(void) {
    // Clear interrupt handlers
    for (int i = 0; i < MAX_INTERRUPTS; i++) {
        interrupt_handlers[i] = 0;
    }
}

// Register an interrupt handler
void register_interrupt_handler(uint8_t num, void (*handler)(void)) {
    if (num < MAX_INTERRUPTS) {
        interrupt_handlers[num] = handler;
    }
}

// System call implementations
int sys_fork(void) {
    struct process* child = proc_create(current_process->name);
    if (!child) return -1;
    
    // Copy parent's memory space
    copy_process_memory(child, current_process);
    
    // Set up child's registers
    child->esp = current_process->esp;
    child->ebp = current_process->ebp;
    child->eip = current_process->eip;
    child->eflags = current_process->eflags;
    
    // Set return value for child (0) and parent (child's PID)
    if (child->pid == 0) {
        return 0; // Child process
    } else {
        return child->pid; // Parent process
    }
}

int sys_execve(const char* filename, char* const argv[], char* const envp[]) {
    if (!filename) return -1;
    
    // Load the executable
    void* entry_point;
    void* stack_top;
    if (fs_executable_load(filename, &entry_point, &stack_top) < 0) {
        return -1;
    }
    
    // Clear existing memory mappings
    for (int i = 0; i < 1024; i++) {
        if (current_process->page_directory[i] & PAGE_PRESENT) {
            page_table_t table = (page_table_t)(current_process->page_directory[i] & PAGE_MASK);
            for (int j = 0; j < 1024; j++) {
                if (table[j] & PAGE_PRESENT) {
                    void* page = (void*)(table[j] & PAGE_MASK);
                    unmap_page((void*)((i << 22) | (j << 12)));
                    free_page(page);
                }
            }
            free_page(table);
            current_process->page_directory[i] = 0;
        }
    }
    
    // Map the new program
    map_page(entry_point, (void*)0x100000, PAGE_PRESENT | PAGE_RW | PAGE_USER);
    
    // Set up new program context
    current_process->eip = (uint32_t)entry_point;
    current_process->esp = (uint32_t)stack_top;
    
    // Set up program arguments and environment
    uint32_t* stack = (uint32_t*)stack_top;
    
    // Push environment variables
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            *(--stack) = (uint32_t)envp[i];
        }
    }
    *(--stack) = 0; // End of environment
    
    // Push arguments
    if (argv) {
        for (int i = 0; argv[i]; i++) {
            *(--stack) = (uint32_t)argv[i];
        }
    }
    *(--stack) = 0; // End of arguments
    
    // Push argument count
    *(--stack) = argv ? (uint32_t)argv[0] : 0;
    
    // Update stack pointer
    current_process->esp = (uint32_t)stack;
    
    return 0;
}

int sys_exit(int status) {
    if (!current_process) return -1;
    
    // Store exit status in process structure
    current_process->exit_status = status;
    current_process->state = PROC_ZOMBIE;
    
    // Wake up parent if it's waiting
    struct process* parent = find_process(current_process->parent_pid);
    if (parent && parent->state == PROC_BLOCKED) {
        parent->state = PROC_READY;
    }
    
    proc_schedule();
    return 0;
}

int sys_waitpid(int pid, int* status, int options) {
    struct process* child;
    
    if (pid > 0) {
        // Wait for specific child
        child = find_process(pid);
        if (!child || child->parent_pid != current_process->pid) {
            return -1;
        }
    } else if (pid == -1) {
        // Wait for any child
        child = process_list;
        while (child) {
            if (child->parent_pid == current_process->pid && 
                child->state == PROC_ZOMBIE) {
                break;
            }
            child = child->next;
        }
    } else {
        return -1;
    }
    
    if (!child) {
        return -1;
    }
    
    // Wait for child to exit
    while (child->state != PROC_ZOMBIE) {
        current_process->state = PROC_BLOCKED;
        proc_schedule();
    }
    
    // Return child's exit status
    if (status) {
        *status = child->exit_status;
    }
    
    proc_destroy(child);
    return child->pid;
}

// File descriptor management system calls
int sys_dup(int oldfd) {
    if (!current_process) return -1;
    return fd_dup(current_process, oldfd);
}

int sys_dup2(int oldfd, int newfd) {
    if (!current_process) return -1;
    return fd_dup2(current_process, oldfd, newfd);
}

int sys_pipe(int pipefd[2]) {
    if (!current_process || !pipefd) return -1;
    
    // Create pipe device
    struct device* pipe = kmalloc(sizeof(struct device));
    if (!pipe) return -1;
    
    pipe->type = DEV_PIPE;
    pipe->major = next_major++;
    pipe->minor = 0;
    pipe->read = pipe_read;
    pipe->write = pipe_write;
    pipe->ioctl = pipe_ioctl;
    
    if (dev_register(pipe) < 0) {
        kfree(pipe);
        return -1;
    }
    
    // Allocate file descriptors
    int readfd = fd_alloc(current_process);
    int writefd = fd_alloc(current_process);
    
    if (readfd < 0 || writefd < 0) {
        if (readfd >= 0) fd_free(current_process, readfd);
        if (writefd >= 0) fd_free(current_process, writefd);
        return -1;
    }
    
    // Set up file descriptors
    struct file_descriptor* read = fd_table[readfd];
    struct file_descriptor* write = fd_table[writefd];
    
    read->dev = pipe;
    write->dev = pipe;
    read->flags = FD_NONBLOCK;
    write->flags = FD_NONBLOCK;
    
    pipefd[0] = readfd;
    pipefd[1] = writefd;
    
    return 0;
}

// Working directory system calls
int sys_chdir(const char* path) {
    if (!current_process || !path) return -1;
    
    uint32_t inode;
    if (fs_path_to_inode(path, &inode) < 0) return -1;
    
    struct inode* dir = fs_get_inode(inode);
    if (!dir || dir->type != FT_DIR) return -1;
    
    // Check execute permission
    struct file* dir_file = fs_open(path, FF_OPEN);
    if (!dir_file) return -1;
    if (fs_check_permissions(dir_file, FP_EXEC) < 0) {
        fs_close(dir_file);
        return -1;
    }
    
    // Update working directory
    strncpy(current_process->cwd, path, MAX_FILENAME - 1);
    current_process->cwd[MAX_FILENAME - 1] = '\0';
    
    fs_close(dir_file);
    return 0;
}

char* sys_getcwd(char* buf, size_t size) {
    if (!current_process || !buf || size == 0) return 0;
    
    size_t len = strlen(current_process->cwd);
    if (len >= size) return 0;
    
    strcpy(buf, current_process->cwd);
    return buf;
}

// Process information system calls
pid_t sys_getpid(void) {
    return current_process ? current_process->pid : 0;
}

pid_t sys_getppid(void) {
    return current_process ? current_process->parent_pid : 0;
}

// User/group management system calls
int sys_setuid(uid_t uid) {
    if (!current_process) return -1;
    
    // Only root can change UID
    if (current_process->uid != ROOT_UID) return -1;
    
    current_process->uid = uid;
    return 0;
}

int sys_setgid(gid_t gid) {
    if (!current_process) return -1;
    
    // Only root can change GID
    if (current_process->uid != ROOT_UID) return -1;
    
    current_process->gid = gid;
    return 0;
}

// Terminal control system calls
int sys_ioctl(int fd, int request, void* arg) {
    if (!current_process) return -1;
    
    struct file_descriptor* fd_entry = fd_get(current_process, fd);
    if (!fd_entry || !fd_entry->dev) return -1;
    
    return dev_ioctl(fd_entry->dev, request, arg);
}

// Signal-related system calls
int sys_signal(int signum, void (*handler)(int)) {
    struct sigaction act, oldact;
    act.sa_handler = handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    
    if (signal_register(signum, &act, &oldact) < 0) {
        return -1;
    }
    
    return (int)oldact.sa_handler;
}

int sys_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact) {
    return signal_register(signum, act, oldact);
}

int sys_sigprocmask(int how, const sigset_t* set, sigset_t* oldset) {
    switch (how) {
        case SIG_BLOCK:
            return signal_block(set, oldset);
        case SIG_UNBLOCK:
            return signal_unblock(set, oldset);
        case SIG_SETMASK:
            return signal_set_mask(set, oldset);
        default:
            return -1;
    }
}

int sys_kill(pid_t pid, int signum) {
    return signal_send(pid, signum);
}

int sys_tkill(pid_t tid, int signum) {
    // In our implementation, thread IDs are the same as process IDs
    return signal_send(tid, signum);
}

int sys_tgkill(pid_t tgid, pid_t tid, int signum) {
    struct process* proc = find_process(tid);
    if (!proc || proc->pgid != tgid) {
        return -1;
    }
    return signal_send(tid, signum);
}

int sys_rt_sigaction(int signum, const struct sigaction* act, struct sigaction* oldact, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t)) {
        return -1;
    }
    return signal_register(signum, act, oldact);
}

int sys_rt_sigprocmask(int how, const sigset_t* set, sigset_t* oldset, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t)) {
        return -1;
    }
    return sys_sigprocmask(how, set, oldset);
}

int sys_rt_sigpending(sigset_t* set, size_t sigsetsize) {
    if (sigsetsize != sizeof(sigset_t)) {
        return -1;
    }
    return signal_pending(set);
}

int sys_rt_sigtimedwait(const sigset_t* set, siginfo_t* info, const struct timespec* timeout) {
    // TODO: Implement sigtimedwait
    return -1;
}

uint32_t handle_syscall(uint32_t syscall_no, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5) {
    switch (syscall_no) {
        case 1:  // exit
            return sys_exit(arg1);
        case 2:  // fork
            return sys_fork();
        case 3:  // read
            return sys_read(arg1, (void*)arg2, arg3);
        case 4:  // write
            return sys_write(arg1, (const void*)arg2, arg3);
        case 5:  // open
            return sys_open((const char*)arg1, arg2);
        case 6:  // close
            return sys_close(arg1);
        case 7:  // waitpid
            return sys_waitpid(arg1, (int*)arg2, arg3);
        case 8:  // execve
            return sys_execve((const char*)arg1, (char* const*)arg2, (char* const*)arg3);
        case 9:  // chdir
            return sys_chdir((const char*)arg1);
        case 10: // getcwd
            return sys_getcwd((char*)arg1, arg2);
        case 11: // dup
            return sys_dup(arg1);
        case 12: // dup2
            return sys_dup2(arg1, arg2);
        case 13: // pipe
            return sys_pipe((int*)arg1);
        case 14: // ioctl
            return sys_ioctl(arg1, arg2, (void*)arg3);
        case 15: // getpid
            return sys_getpid();
        case 16: // getppid
            return sys_getppid();
        case 17: // setuid
            return sys_setuid(arg1);
        case 18: // setgid
            return sys_setgid(arg1);
        case 19: // signal
            return sys_signal(arg1, (void (*)(int))arg2);
        case 20: // sigaction
            return sys_sigaction(arg1, (const struct sigaction*)arg2, (struct sigaction*)arg3);
        case 21: // sigprocmask
            return sys_sigprocmask(arg1, (const sigset_t*)arg2, (sigset_t*)arg3);
        case 22: // kill
            return sys_kill(arg1, arg2);
        case 23: // tkill
            return sys_tkill(arg1, arg2);
        case 24: // tgkill
            return sys_tgkill(arg1, arg2, arg3);
        case 25: // rt_sigaction
            return sys_rt_sigaction(arg1, (const struct sigaction*)arg2, (struct sigaction*)arg3, arg4);
        case 26: // rt_sigprocmask
            return sys_rt_sigprocmask(arg1, (const sigset_t*)arg2, (sigset_t*)arg3, arg4);
        case 27: // rt_sigpending
            return sys_rt_sigpending((sigset_t*)arg1, arg2);
        case 28: // rt_sigtimedwait
            return sys_rt_sigtimedwait((const sigset_t*)arg1, (siginfo_t*)arg2, (const struct timespec*)arg3);
        default:
            return -1;
    }
}

void interrupt_handler(struct interrupt_frame* frame) {
    // Save current process context
    if (current_process) {
        current_process->esp = frame->esp;
        current_process->ebp = frame->ebp;
        current_process->eip = frame->eip;
        current_process->eflags = frame->eflags;
    }
    
    // Handle the interrupt
    if (frame->int_no < 32) {
        // Hardware interrupt
        if (interrupt_handlers[frame->int_no]) {
            interrupt_handlers[frame->int_no]();
        }
        
        // Handle keyboard interrupt (IRQ1)
        if (frame->int_no == 33) {
            uint8_t scancode = inb(0x60);
            keyboard_handle_scancode(scancode);
            outb(0x20, 0x20);
        }
        
        // Send EOI to PIC
        if (frame->int_no >= 32) {
            outb(0x20, 0x20);
        }
    } else {
        // System call
        uint32_t syscall_no = frame->eax;
        uint32_t arg1 = frame->ebx;
        uint32_t arg2 = frame->ecx;
        uint32_t arg3 = frame->edx;
        uint32_t arg4 = frame->esi;
        uint32_t arg5 = frame->edi;
        
        frame->eax = handle_syscall(syscall_no, arg1, arg2, arg3, arg4, arg5);
    }
    
    // Check for pending signals
    if (current_process) {
        signal_handle();
    }
    
    // Schedule next process
    proc_schedule();
}

// Create process
struct process* process_create(const char* name) {
    struct process* proc = kmalloc(sizeof(struct process));
    if (!proc) return 0;
    
    // Initialize process structure
    proc->pid = next_pid++;
    strncpy(proc->name, name, sizeof(proc->name) - 1);
    proc->name[sizeof(proc->name) - 1] = '\0';
    proc->parent = 0;
    proc->next = process_list;
    proc->prev = 0;
    proc->children = 0;
    proc->siblings = 0;
    proc->group = 0;
    proc->session = 0;
    proc->state = PROC_NEW;
    proc->flags = 0;
    proc->exit_status = 0;
    memset(&proc->regs, 0, sizeof(struct regs));
    proc->stack = 0;
    proc->stack_size = 0;
    memset(proc->files, 0, sizeof(proc->files));
    proc->cwd = 0;
    memset(&proc->signals, 0, sizeof(struct signal_info));
    
    // Allocate stack
    proc->stack = kmalloc(4096);
    if (!proc->stack) {
        kfree(proc);
        return 0;
    }
    proc->stack_size = 4096;
    
    // Set up page directory
    proc->regs.cr3 = (uint32_t)create_page_directory();
    if (!proc->regs.cr3) {
        kfree(proc->stack);
        kfree(proc);
        return 0;
    }
    
    // Add to process list
    if (process_list) {
        process_list->prev = proc;
    }
    process_list = proc;
    
    return proc;
}

// Destroy process
void process_destroy(struct process* proc) {
    if (!proc) return;
    
    // Remove from process list
    if (proc->prev) {
        proc->prev->next = proc->next;
    } else {
        process_list = proc->next;
    }
    if (proc->next) {
        proc->next->prev = proc->prev;
    }
    
    // Remove from parent's children list
    if (proc->parent) {
        if (proc->parent->children == proc) {
            proc->parent->children = proc->siblings;
        } else {
            struct process* sibling = proc->parent->children;
            while (sibling && sibling->siblings != proc) {
                sibling = sibling->siblings;
            }
            if (sibling) {
                sibling->siblings = proc->siblings;
            }
        }
    }
    
    // Remove from process group
    if (proc->group) {
        if (proc->group->leader == proc) {
            // Move group leadership to another process
            struct process* new_leader = proc->siblings;
            if (new_leader) {
                proc->group->leader = new_leader;
                proc->group->pgid = new_leader->pid;
            } else {
                // No more processes in group, destroy group
                if (proc->group->prev) {
                    proc->group->prev->next = proc->group->next;
                } else {
                    group_list = proc->group->next;
                }
                if (proc->group->next) {
                    proc->group->next->prev = proc->group->prev;
                }
                kfree(proc->group);
            }
        }
    }
    
    // Close all file descriptors
    for (int i = 0; i < MAX_FILES; i++) {
        if (proc->files[i]) {
            fs_close(proc->files[i]);
        }
    }
    
    // Free resources
    if (proc->stack) kfree(proc->stack);
    if (proc->regs.cr3) destroy_page_directory((page_directory_t*)proc->regs.cr3);
    kfree(proc);
}

// Yield CPU
void process_yield(void) {
    struct process* current = get_current_process();
    if (!current) return;
    
    // Save current process state
    save_process_state(current);
    
    // Find next ready process
    struct process* next = process_list;
    while (next) {
        if (next->state == PROC_READY && next != current) {
            break;
        }
        next = next->next;
    }
    
    if (next) {
        // Switch to next process
        current->state = PROC_READY;
        next->state = PROC_RUNNING;
        switch_to_process(next);
    }
}

// Find process by PID
struct process* process_find(pid_t pid) {
    struct process* proc = process_list;
    while (proc) {
        if (proc->pid == pid) {
            return proc;
        }
        proc = proc->next;
    }
    return 0;
}

// Allocate file descriptor
int process_alloc_fd(struct process* proc) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (!proc->files[i]) {
            return i;
        }
    }
    return -1;
}

// Free file descriptor
void process_free_fd(struct process* proc, int fd) {
    if (fd >= 0 && fd < MAX_FILES) {
        if (proc->files[fd]) {
            fs_close(proc->files[fd]);
            proc->files[fd] = 0;
        }
    }
}

// Set process group
int process_set_group(struct process* proc, struct process_group* group) {
    if (!proc || !group) return -1;
    
    // Remove from old group
    if (proc->group) {
        if (proc->group->leader == proc) {
            // Move group leadership to another process
            struct process* new_leader = proc->siblings;
            if (new_leader) {
                proc->group->leader = new_leader;
                proc->group->pgid = new_leader->pid;
            } else {
                // No more processes in group, destroy group
                if (proc->group->prev) {
                    proc->group->prev->next = proc->group->next;
                } else {
                    group_list = proc->group->next;
                }
                if (proc->group->next) {
                    proc->group->next->prev = proc->group->prev;
                }
                kfree(proc->group);
            }
        }
    }
    
    // Add to new group
    proc->group = group;
    if (!group->leader) {
        group->leader = proc;
        group->pgid = proc->pid;
    }
    
    return 0;
}

// Set process session
int process_set_session(struct process* proc, struct process_group* session) {
    if (!proc || !session) return -1;
    
    // Remove from old session
    if (proc->session) {
        // TODO: Handle session cleanup
    }
    
    // Add to new session
    proc->session = session;
    
    return 0;
}

// Set process terminal
int process_set_terminal(struct process* proc, struct terminal* terminal) {
    if (!proc || !proc->group) return -1;
    
    proc->group->terminal = terminal;
    return 0;
}

// Send signal to process
void process_send_signal(struct process* proc, int signum, struct siginfo* info) {
    if (!proc || signum < 0 || signum >= 32) return;
    
    // Check if signal is blocked
    if (proc->signals.blocked & (1 << signum)) {
        return;
    }
    
    // Add to pending signals
    proc->signals.pending |= (1 << signum);
    if (info) {
        proc->signals.pending_info[signum] = *info;
    }
    
    // Wake up process if blocked
    if (proc->state == PROC_BLOCKED) {
        proc->state = PROC_READY;
    }
}

// Handle signal
void process_handle_signal(struct process* proc, int signum) {
    if (!proc || signum < 0 || signum >= 32) return;
    
    // Get signal action
    struct sigaction* sa = &proc->signals.actions[signum];
    
    // Handle signal based on action
    switch (sa->sa_handler) {
        case SIG_DFL:
            // Default action
            switch (signum) {
                case SIGCHLD:
                    // Ignore
                    break;
                case SIGCONT:
                    process_continue(proc);
                    break;
                case SIGSTOP:
                    process_stop(proc);
                    break;
                case SIGTSTP:
                    process_stop(proc);
                    break;
                case SIGTTIN:
                    process_stop(proc);
                    break;
                case SIGTTOU:
                    process_stop(proc);
                    break;
                default:
                    process_exit(proc, 128 + signum);
                    break;
            }
            break;
            
        case SIG_IGN:
            // Ignore signal
            break;
            
        default:
            // Call signal handler
            // TODO: Set up signal handler call
            break;
    }
}

// Check for pending signals
void process_check_signals(struct process* proc) {
    if (!proc) return;
    
    // Check each signal
    for (int i = 0; i < 32; i++) {
        if (proc->signals.pending & (1 << i)) {
            process_handle_signal(proc, i);
            proc->signals.pending &= ~(1 << i);
        }
    }
}

// Wait for child process
void process_wait_for_child(struct process* proc) {
    if (!proc) return;
    
    // Find zombie child
    struct process* child = proc->children;
    while (child) {
        if (child->state == PROC_ZOMBIE) {
            // Get exit status
            proc->exit_status = child->exit_status;
            
            // Clean up child
            process_destroy(child);
            return;
        }
        child = child->siblings;
    }
    
    // No zombie children, block
    proc->state = PROC_BLOCKED;
    process_yield();
}

// Exit process
void process_exit(struct process* proc, int status) {
    if (!proc) return;
    
    // Set exit status
    proc->exit_status = status;
    
    // Set state to zombie
    proc->state = PROC_ZOMBIE;
    
    // Wake up parent if waiting
    if (proc->parent && proc->parent->state == PROC_BLOCKED) {
        proc->parent->state = PROC_READY;
    }
    
    // Yield CPU
    process_yield();
}

// Stop process
void process_stop(struct process* proc) {
    if (!proc) return;
    
    // Set stopped flag
    proc->flags |= PF_STOPPED;
    
    // Update process group
    if (proc->group) {
        proc->group->flags |= PGRP_STOPPED;
    }
    
    // Wake up parent if waiting
    if (proc->parent && proc->parent->state == PROC_BLOCKED) {
        proc->parent->state = PROC_READY;
    }
    
    // Yield CPU
    process_yield();
}

// Continue process
void process_continue(struct process* proc) {
    if (!proc) return;
    
    // Clear stopped flag
    proc->flags &= ~PF_STOPPED;
    
    // Update process group
    if (proc->group) {
        proc->group->flags &= ~PGRP_STOPPED;
    }
    
    // Set state to ready
    proc->state = PROC_READY;
}

// Put process in foreground
void process_put_in_foreground(struct process* proc) {
    if (!proc || !proc->group) return;
    
    // Set foreground flags
    proc->flags |= PF_FOREGROUND;
    proc->group->flags |= PGRP_FOREGROUND;
    
    // Set terminal foreground process group
    if (proc->group->terminal) {
        terminal_set_foreground_group(proc->group->terminal, proc->group);
    }
}

// Put process in background
void process_put_in_background(struct process* proc) {
    if (!proc || !proc->group) return;
    
    // Set background flags
    proc->flags |= PF_BACKGROUND;
    proc->group->flags |= PGRP_BACKGROUND;
    
    // Clear terminal foreground process group
    if (proc->group->terminal) {
        terminal_set_foreground_group(proc->group->terminal, 0);
    }
} 