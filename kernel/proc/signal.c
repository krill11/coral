#include "signal.h"
#include "process.h"
#include "../mm/memory.h"
#include <string.h>

// Signal handler table
#define MAX_SIGNALS 32
static struct sigaction signal_handlers[MAX_SIGNALS];
static sigset_t signal_mask;
static sigset_t pending_signals;

// Signal stack
#define SIGSTACK_SIZE 4096
static void* signal_stack = 0;

// Initialize signal handling
int signal_init(void) {
    // Allocate signal stack
    signal_stack = get_page();
    if (!signal_stack) return -1;
    
    // Initialize signal handlers
    memset(signal_handlers, 0, sizeof(signal_handlers));
    
    // Initialize signal masks
    memset(&signal_mask, 0, sizeof(sigset_t));
    memset(&pending_signals, 0, sizeof(sigset_t));
    
    return 0;
}

// Register signal handler
int signal_register(int signum, const struct sigaction* act, struct sigaction* oldact) {
    if (signum < 1 || signum > MAX_SIGNALS) return -1;
    
    // Save old handler if requested
    if (oldact) {
        memcpy(oldact, &signal_handlers[signum - 1], sizeof(struct sigaction));
    }
    
    // Set new handler
    if (act) {
        memcpy(&signal_handlers[signum - 1], act, sizeof(struct sigaction));
    }
    
    return 0;
}

// Send signal to process
int signal_send(pid_t pid, int signum) {
    if (signum < 1 || signum > MAX_SIGNALS) return -1;
    
    struct process* proc = find_process(pid);
    if (!proc) return -1;
    
    // Set pending signal
    pending_signals.sig[signum / 32] |= (1 << (signum % 32));
    
    // Wake up process if it's blocked
    if (proc->state == PROC_BLOCKED) {
        proc->state = PROC_READY;
    }
    
    return 0;
}

// Send signal to process group
int signal_send_group(pid_t pgid, int signum) {
    if (signum < 1 || signum > MAX_SIGNALS) return -1;
    
    struct process* proc = process_list;
    while (proc) {
        if (proc->pgid == pgid) {
            signal_send(proc->pid, signum);
        }
        proc = proc->next;
    }
    
    return 0;
}

// Block signals
int signal_block(const sigset_t* set, sigset_t* oldset) {
    if (!set) return -1;
    
    // Save old mask if requested
    if (oldset) {
        memcpy(oldset, &signal_mask, sizeof(sigset_t));
    }
    
    // Update signal mask
    for (int i = 0; i < 2; i++) {
        signal_mask.sig[i] |= set->sig[i];
    }
    
    return 0;
}

// Unblock signals
int signal_unblock(const sigset_t* set, sigset_t* oldset) {
    if (!set) return -1;
    
    // Save old mask if requested
    if (oldset) {
        memcpy(oldset, &signal_mask, sizeof(sigset_t));
    }
    
    // Update signal mask
    for (int i = 0; i < 2; i++) {
        signal_mask.sig[i] &= ~set->sig[i];
    }
    
    return 0;
}

// Set signal mask
int signal_set_mask(const sigset_t* set, sigset_t* oldset) {
    if (!set) return -1;
    
    // Save old mask if requested
    if (oldset) {
        memcpy(oldset, &signal_mask, sizeof(sigset_t));
    }
    
    // Set new mask
    memcpy(&signal_mask, set, sizeof(sigset_t));
    
    return 0;
}

// Check for pending signals
int signal_pending(sigset_t* set) {
    if (!set) return -1;
    
    // Get pending signals that aren't blocked
    for (int i = 0; i < 2; i++) {
        set->sig[i] = pending_signals.sig[i] & ~signal_mask.sig[i];
    }
    
    return 0;
}

// Handle pending signals
void signal_handle(void) {
    sigset_t pending;
    if (signal_pending(&pending) < 0) return;
    
    // Check each signal
    for (int i = 0; i < MAX_SIGNALS; i++) {
        if (pending.sig[i / 32] & (1 << (i % 32))) {
            struct sigaction* handler = &signal_handlers[i];
            
            // Clear pending signal
            pending_signals.sig[i / 32] &= ~(1 << (i % 32));
            
            // Handle signal
            if (handler->sa_handler) {
                // Save current context
                uint32_t old_esp = current_process->esp;
                uint32_t old_eip = current_process->eip;
                
                // Set up signal handler stack
                if (handler->sa_flags & SA_ONSTACK) {
                    current_process->esp = (uint32_t)signal_stack + SIGSTACK_SIZE - 16;
                }
                
                // Push signal handler arguments
                uint32_t* stack = (uint32_t*)current_process->esp;
                *(--stack) = i;  // Signal number
                
                // Set up return address
                *(--stack) = old_eip;
                
                // Update process context
                current_process->esp = (uint32_t)stack;
                current_process->eip = (uint32_t)handler->sa_handler;
                
                // Handle SA_RESETHAND flag
                if (handler->sa_flags & SA_RESETHAND) {
                    handler->sa_handler = 0;
                }
            }
        }
    }
} 