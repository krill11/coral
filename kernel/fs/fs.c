#include "fs.h"
#include "elf.h"
#include "dynamic.h"
#include "../proc/process.h"
#include "../drivers/terminal.h"
#include <string.h>
#include <stddef.h>

// Forward declarations
extern struct process* current_process;

// IOCTL commands
#define FIONREAD  0x541B  // Get number of bytes available to read
#define FIONWRITE 0x541C  // Get number of bytes that can be written

// Root directory inode
#define ROOT_INODE 1

// Filesystem state
static struct inode* inode_table = 0;
static uint32_t inode_count = 0;
static struct file* open_files = 0;
static uint8_t* block_bitmap = 0;
static uint32_t block_count = 0;

// Device management
#define MAX_DEVICES 64
static struct device* devices[MAX_DEVICES];
static int next_major = 1;

// Terminal management
#define MAX_TERMINALS 8
static struct termios terminal_settings[MAX_TERMINALS];
static struct winsize terminal_windows[MAX_TERMINALS];
static pid_t terminal_groups[MAX_TERMINALS];

// File descriptor management
#define MAX_FDS 1024
static struct file_descriptor* fd_table[MAX_FDS];

// Pipe buffer size
#define PIPE_BUFFER_SIZE 4096

// Pipe structure
struct pipe {
    char buffer[PIPE_BUFFER_SIZE];
    size_t read_pos;
    size_t write_pos;
    size_t count;
    int readers;
    int writers;
};

// Initialize filesystem
void fs_init(void) {
    // Allocate inode table
    inode_table = kmalloc(sizeof(struct inode) * 1024);
    if (!inode_table) return;
    
    // Allocate block bitmap (1 bit per block)
    block_count = 1024 * 1024; // 1GB filesystem
    block_bitmap = kmalloc(block_count / 8);
    if (!block_bitmap) {
        kfree(inode_table);
        return;
    }
    memset(block_bitmap, 0, block_count / 8);
    
    // Create root directory
    struct inode* root = &inode_table[ROOT_INODE];
    root->inode_num = ROOT_INODE;
    root->size = 0;
    root->type = FT_DIR;
    root->permissions = FP_READ | FP_WRITE | FP_EXEC;
    root->block_count = 0;
    
    inode_count = 1024;
    
    // Initialize dynamic linking
    dynamic_init();
    
    // Initialize terminal management
    tty_init();
}

// Block management
void* fs_get_block(uint32_t block_num) {
    if (block_num >= block_count) return 0;
    
    // Check if block is allocated
    if (!(block_bitmap[block_num / 8] & (1 << (block_num % 8)))) {
        return 0;
    }
    
    // Return block address
    return (void*)(0x1000000 + (block_num * BLOCK_SIZE));
}

void fs_free_block(uint32_t block_num) {
    if (block_num >= block_count) return;
    
    // Clear bit in bitmap
    block_bitmap[block_num / 8] &= ~(1 << (block_num % 8));
}

int fs_allocate_blocks(struct inode* inode, uint32_t num_blocks) {
    if (!inode || num_blocks == 0) return -1;
    
    // Find free blocks
    uint32_t* new_blocks = kmalloc(sizeof(uint32_t) * num_blocks);
    if (!new_blocks) return -1;
    
    uint32_t found = 0;
    for (uint32_t i = 0; i < block_count && found < num_blocks; i++) {
        if (!(block_bitmap[i / 8] & (1 << (i % 8)))) {
            block_bitmap[i / 8] |= (1 << (i % 8));
            new_blocks[found++] = i;
        }
    }
    
    if (found < num_blocks) {
        // Free allocated blocks
        for (uint32_t i = 0; i < found; i++) {
            fs_free_block(new_blocks[i]);
        }
        kfree(new_blocks);
        return -1;
    }
    
    // Update inode
    if (inode->block_count < 12) {
        // Use direct blocks
        for (uint32_t i = 0; i < num_blocks; i++) {
            inode->blocks[inode->block_count++] = new_blocks[i];
        }
    } else if (inode->block_count < 12 + 1024) {
        // Use indirect block
        if (!inode->indirect) {
            inode->indirect = new_blocks[0];
            uint32_t* indirect_table = fs_get_block(inode->indirect);
            if (!indirect_table) {
                fs_free_block(inode->indirect);
                kfree(new_blocks);
                return -1;
            }
            for (uint32_t i = 1; i < num_blocks; i++) {
                indirect_table[i-1] = new_blocks[i];
            }
        }
    }
    
    kfree(new_blocks);
    return 0;
}

// Get inode by number
struct inode* fs_get_inode(uint32_t inode_num) {
    if (inode_num >= inode_count) return 0;
    return &inode_table[inode_num];
}

// Path traversal
int fs_path_to_inode(const char* path, uint32_t* inode_num) {
    if (!path || !inode_num) return -1;
    
    // Handle root directory
    if (path[0] == '/' && path[1] == '\0') {
        *inode_num = ROOT_INODE;
        return 0;
    }
    
    // Start from root
    uint32_t current_inode = ROOT_INODE;
    char component[MAX_FILENAME];
    const char* path_ptr = path;
    
    while (*path_ptr) {
        // Skip leading slash
        if (*path_ptr == '/') {
            path_ptr++;
            continue;
        }
        
        // Get next component
        size_t i = 0;
        while (*path_ptr && *path_ptr != '/' && i < MAX_FILENAME - 1) {
            component[i++] = *path_ptr++;
        }
        component[i] = '\0';
        
        // Look up component in current directory
        struct inode* dir = fs_get_inode(current_inode);
        if (!dir || dir->type != FT_DIR) return -1;
        
        struct dir_entry entry;
        struct file* dir_file = fs_open("/", FF_OPEN);
        if (!dir_file) return -1;
        
        int found = 0;
        while (fs_readdir(dir_file, &entry) == 0) {
            if (strcmp(entry.name, component) == 0) {
                current_inode = entry.inode;
                found = 1;
                break;
            }
        }
        
        fs_close(dir_file);
        if (!found) return -1;
    }
    
    *inode_num = current_inode;
    return 0;
}

// Check file permissions
int fs_check_permissions(struct file* file, uint32_t required) {
    if (!file) return -1;
    
    struct inode* inode = fs_get_inode(file->inode);
    if (!inode) return -1;
    
    // Root has all permissions
    if (current_process && current_process->uid == ROOT_UID) {
        return 0;
    }
    
    // Check owner permissions
    if (current_process && current_process->uid == inode->uid) {
        if ((required & inode->permissions) == required) {
            return 0;
        }
    }
    
    // Check group permissions
    if (current_process && current_process->gid == inode->gid) {
        if ((required & (inode->permissions >> 3)) == required) {
            return 0;
        }
    }
    
    // Check other permissions
    if ((required & (inode->permissions >> 6)) == required) {
        return 0;
    }
    
    return -1;
}

// Open a file
struct file* fs_open(const char* path, uint32_t flags) {
    if (!path) return 0;
    
    uint32_t inode_num;
    if (fs_path_to_inode(path, &inode_num) < 0) return 0;
    
    struct inode* inode = fs_get_inode(inode_num);
    if (!inode) return 0;
    
    struct file* file = kmalloc(sizeof(struct file));
    if (!file) return 0;
    
    file->inode = inode_num;
    file->size = inode->size;
    file->type = inode->type;
    file->permissions = inode->permissions;
    file->flags = flags;
    file->ref_count = 1;
    file->next = 0;
    
    // Add to open files list
    if (!open_files) {
        open_files = file;
    } else {
        struct file* f = open_files;
        while (f->next) f = f->next;
        f->next = file;
    }
    
    return file;
}

// Close a file
int fs_close(struct file* file) {
    if (!file) return -1;
    
    file->ref_count--;
    if (file->ref_count == 0) {
        // Remove from open files list
        if (open_files == file) {
            open_files = file->next;
        } else {
            struct file* f = open_files;
            while (f && f->next != file) f = f->next;
            if (f) f->next = file->next;
        }
        
        kfree(file);
    }
    
    return 0;
}

// Read from a file
int fs_read(struct file* file, void* buffer, size_t size, size_t offset) {
    if (!file || !buffer) return -1;
    if (fs_check_permissions(file, FP_READ) < 0) return -1;
    
    struct inode* inode = fs_get_inode(file->inode);
    if (!inode) return -1;
    
    // Check bounds
    if (offset >= inode->size) return 0;
    if (offset + size > inode->size) {
        size = inode->size - offset;
    }
    
    // Calculate blocks to read
    uint32_t start_block = offset / BLOCK_SIZE;
    uint32_t end_block = (offset + size - 1) / BLOCK_SIZE;
    uint32_t bytes_read = 0;
    
    for (uint32_t block = start_block; block <= end_block; block++) {
        void* block_addr = 0;
        if (block < 12) {
            block_addr = fs_get_block(inode->blocks[block]);
        } else if (block < 12 + 1024) {
            uint32_t* indirect_table = fs_get_block(inode->indirect);
            if (!indirect_table) continue;
            block_addr = fs_get_block(indirect_table[block - 12]);
        }
        
        if (!block_addr) continue;
        
        // Calculate read position within block
        size_t block_offset = block == start_block ? offset % BLOCK_SIZE : 0;
        size_t block_size = block == end_block ? 
            size - bytes_read : 
            BLOCK_SIZE - block_offset;
        
        // Copy data
        memcpy((char*)buffer + bytes_read, 
               (char*)block_addr + block_offset, 
               block_size);
        
        bytes_read += block_size;
    }
    
    return bytes_read;
}

// Write to a file
int fs_write(struct file* file, const void* buffer, size_t size, size_t offset) {
    if (!file || !buffer) return -1;
    if (fs_check_permissions(file, FP_WRITE) < 0) return -1;
    
    struct inode* inode = fs_get_inode(file->inode);
    if (!inode) return -1;
    
    // Calculate required blocks
    uint32_t required_blocks = (offset + size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint32_t current_blocks = inode->block_count;
    
    // Allocate additional blocks if needed
    if (required_blocks > current_blocks) {
        if (fs_allocate_blocks(inode, required_blocks - current_blocks) < 0) {
            return -1;
        }
    }
    
    // Calculate blocks to write
    uint32_t start_block = offset / BLOCK_SIZE;
    uint32_t end_block = (offset + size - 1) / BLOCK_SIZE;
    uint32_t bytes_written = 0;
    
    for (uint32_t block = start_block; block <= end_block; block++) {
        void* block_addr = 0;
        if (block < 12) {
            block_addr = fs_get_block(inode->blocks[block]);
        } else if (block < 12 + 1024) {
            uint32_t* indirect_table = fs_get_block(inode->indirect);
            if (!indirect_table) continue;
            block_addr = fs_get_block(indirect_table[block - 12]);
        }
        
        if (!block_addr) continue;
        
        // Calculate write position within block
        size_t block_offset = block == start_block ? offset % BLOCK_SIZE : 0;
        size_t block_size = block == end_block ? 
            size - bytes_written : 
            BLOCK_SIZE - block_offset;
        
        // Copy data
        memcpy((char*)block_addr + block_offset, 
               (char*)buffer + bytes_written, 
               block_size);
        
        bytes_written += block_size;
    }
    
    // Update file size
    if (offset + size > inode->size) {
        inode->size = offset + size;
    }
    
    return bytes_written;
}

// Directory operations
int fs_readdir(struct file* dir, struct dir_entry* entry) {
    if (!dir || !entry) return -1;
    
    struct inode* inode = fs_get_inode(dir->inode);
    if (!inode || inode->type != FT_DIR) return -1;
    
    // Read directory entry at current position
    if (fs_read(dir, entry, sizeof(struct dir_entry), dir->pos) != sizeof(struct dir_entry)) {
        return -1;
    }
    
    dir->pos += entry->rec_len;
    return 0;
}

// Load an executable file
int fs_executable_load(const char* path, void** entry_point, void** stack_top) {
    if (!path || !entry_point || !stack_top) return -1;
    
    struct file* file = fs_open(path, FF_OPEN);
    if (!file) return -1;
    
    struct inode* inode = fs_get_inode(file->inode);
    if (!inode) {
        fs_close(file);
        return -1;
    }
    
    // Check if file is executable
    if (inode->type != FT_FILE || !(inode->permissions & FP_EXEC)) {
        fs_close(file);
        return -1;
    }
    
    // Allocate memory for the file
    void* file_data = kmalloc(inode->size);
    if (!file_data) {
        fs_close(file);
        return -1;
    }
    
    // Read file into memory
    if (fs_read(file, file_data, inode->size, 0) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Parse ELF header
    struct elf32_header* header = (struct elf32_header*)file_data;
    
    // Validate ELF header
    if (elf_validate_header(header) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Load required libraries
    if (dynamic_load_required_libs(header) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Load program headers
    if (elf_load_program_headers(header, file_data) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Load sections
    if (elf_load_sections(header, file_data) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Set up memory protection
    if (elf_setup_memory_protection(header) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Perform dynamic relocations
    if (dynamic_relocate(header) < 0) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Get entry point
    *entry_point = elf_get_entry_point(header);
    
    // Set up stack
    void* stack = get_page();
    if (!stack) {
        kfree(file_data);
        fs_close(file);
        return -1;
    }
    
    // Map stack with read/write permissions
    map_page(stack, (void*)(0x8000000 - PAGE_SIZE), 
             PAGE_PRESENT | PAGE_RW | PAGE_USER);
    
    *stack_top = (void*)(0x8000000 - 16);
    
    // Free file data
    kfree(file_data);
    fs_close(file);
    
    return 0;
}

// Create a new file
int fs_create_file(const char* path, uint32_t type, uint32_t permissions) {
    if (!path) return -1;
    
    // Find parent directory
    char parent_path[MAX_FILENAME];
    char filename[MAX_FILENAME];
    const char* last_slash = strrchr(path, '/');
    
    if (last_slash) {
        size_t parent_len = last_slash - path;
        if (parent_len >= MAX_FILENAME) return -1;
        strncpy(parent_path, path, parent_len);
        parent_path[parent_len] = '\0';
        strcpy(filename, last_slash + 1);
    } else {
        strcpy(filename, path);
        strcpy(parent_path, "/");
    }
    
    // Get parent directory inode
    uint32_t parent_inode;
    if (fs_path_to_inode(parent_path, &parent_inode) < 0) return -1;
    
    struct inode* parent = fs_get_inode(parent_inode);
    if (!parent || parent->type != FT_DIR) return -1;
    
    // Check write permission on parent
    struct file* parent_file = fs_open(parent_path, FF_OPEN);
    if (!parent_file) return -1;
    if (fs_check_permissions(parent_file, FP_WRITE) < 0) {
        fs_close(parent_file);
        return -1;
    }
    
    // Create new inode
    uint32_t new_inode = 0;
    for (uint32_t i = 1; i < inode_count; i++) {
        if (!inode_table[i].inode_num) {
            new_inode = i;
            break;
        }
    }
    if (!new_inode) {
        fs_close(parent_file);
        return -1;
    }
    
    // Initialize new inode
    struct inode* inode = &inode_table[new_inode];
    inode->inode_num = new_inode;
    inode->size = 0;
    inode->type = type;
    inode->permissions = permissions;
    inode->uid = current_process ? current_process->uid : ROOT_UID;
    inode->gid = current_process ? current_process->gid : ROOT_GID;
    inode->block_count = 0;
    
    // Create directory entry
    struct dir_entry entry;
    entry.inode = new_inode;
    entry.name_len = strlen(filename);
    entry.file_type = type;
    strcpy(entry.name, filename);
    entry.rec_len = sizeof(struct dir_entry);
    
    // Write directory entry
    if (fs_write(parent_file, &entry, sizeof(struct dir_entry), parent->size) < 0) {
        inode->inode_num = 0;
        fs_close(parent_file);
        return -1;
    }
    
    parent->size += sizeof(struct dir_entry);
    fs_close(parent_file);
    return 0;
}

// Delete a file
int fs_delete_file(const char* path) {
    if (!path) return -1;
    
    // Find parent directory
    char parent_path[MAX_FILENAME];
    char filename[MAX_FILENAME];
    const char* last_slash = strrchr(path, '/');
    
    if (last_slash) {
        size_t parent_len = last_slash - path;
        if (parent_len >= MAX_FILENAME) return -1;
        strncpy(parent_path, path, parent_len);
        parent_path[parent_len] = '\0';
        strcpy(filename, last_slash + 1);
    } else {
        strcpy(filename, path);
        strcpy(parent_path, "/");
    }
    
    // Get parent directory inode
    uint32_t parent_inode;
    if (fs_path_to_inode(parent_path, &parent_inode) < 0) return -1;
    
    struct inode* parent = fs_get_inode(parent_inode);
    if (!parent || parent->type != FT_DIR) return -1;
    
    // Check write permission on parent
    struct file* parent_file = fs_open(parent_path, FF_OPEN);
    if (!parent_file) return -1;
    if (fs_check_permissions(parent_file, FP_WRITE) < 0) {
        fs_close(parent_file);
        return -1;
    }
    
    // Find and remove directory entry
    struct dir_entry entry;
    size_t offset = 0;
    int found = 0;
    
    while (fs_read(parent_file, &entry, sizeof(struct dir_entry), offset) == sizeof(struct dir_entry)) {
        if (strcmp(entry.name, filename) == 0) {
            // Get target inode
            struct inode* target = fs_get_inode(entry.inode);
            if (!target) {
                fs_close(parent_file);
                return -1;
            }
            
            // Free blocks
            for (uint32_t i = 0; i < target->block_count; i++) {
                if (i < 12) {
                    fs_free_block(target->blocks[i]);
                } else if (i < 12 + 1024) {
                    uint32_t* indirect_table = fs_get_block(target->indirect);
                    if (indirect_table) {
                        fs_free_block(indirect_table[i - 12]);
                    }
                }
            }
            
            // Free indirect block if exists
            if (target->indirect) {
                fs_free_block(target->indirect);
            }
            
            // Clear inode
            target->inode_num = 0;
            target->size = 0;
            target->block_count = 0;
            
            // Remove directory entry
            if (offset + entry.rec_len < parent->size) {
                // Move remaining entries
                struct dir_entry next_entry;
                size_t next_offset = offset + entry.rec_len;
                while (fs_read(parent_file, &next_entry, sizeof(struct dir_entry), next_offset) == sizeof(struct dir_entry)) {
                    fs_write(parent_file, &next_entry, sizeof(struct dir_entry), offset);
                    offset += next_entry.rec_len;
                    next_offset += next_entry.rec_len;
                }
            }
            
            parent->size -= entry.rec_len;
            found = 1;
            break;
        }
        offset += entry.rec_len;
    }
    
    fs_close(parent_file);
    return found ? 0 : -1;
}

// Create a directory
int fs_mkdir(const char* path) {
    if (!path) return -1;
    
    // Create directory inode
    if (fs_create_file(path, FT_DIR, FP_READ | FP_WRITE | FP_EXEC) < 0) {
        return -1;
    }
    
    // Get directory inode
    uint32_t dir_inode;
    if (fs_path_to_inode(path, &dir_inode) < 0) return -1;
    
    struct inode* dir = fs_get_inode(dir_inode);
    if (!dir) return -1;
    
    // Create . and .. entries
    struct dir_entry dot, dotdot;
    
    // . entry
    dot.inode = dir_inode;
    dot.name_len = 1;
    dot.file_type = FT_DIR;
    strcpy(dot.name, ".");
    dot.rec_len = sizeof(struct dir_entry);
    
    // .. entry
    dotdot.inode = ROOT_INODE;  // Parent directory
    dotdot.name_len = 2;
    dotdot.file_type = FT_DIR;
    strcpy(dotdot.name, "..");
    dotdot.rec_len = sizeof(struct dir_entry);
    
    // Write entries
    struct file* dir_file = fs_open(path, FF_OPEN);
    if (!dir_file) return -1;
    
    if (fs_write(dir_file, &dot, sizeof(struct dir_entry), 0) < 0 ||
        fs_write(dir_file, &dotdot, sizeof(struct dir_entry), sizeof(struct dir_entry)) < 0) {
        fs_close(dir_file);
        return -1;
    }
    
    dir->size = 2 * sizeof(struct dir_entry);
    fs_close(dir_file);
    return 0;
}

// Remove a directory
int fs_rmdir(const char* path) {
    if (!path) return -1;
    
    // Get directory inode
    uint32_t dir_inode;
    if (fs_path_to_inode(path, &dir_inode) < 0) return -1;
    
    struct inode* dir = fs_get_inode(dir_inode);
    if (!dir || dir->type != FT_DIR) return -1;
    
    // Check if directory is empty
    struct file* dir_file = fs_open(path, FF_OPEN);
    if (!dir_file) return -1;
    
    struct dir_entry entry;
    size_t entry_count = 0;
    
    while (fs_read(dir_file, &entry, sizeof(struct dir_entry), entry_count * sizeof(struct dir_entry)) == sizeof(struct dir_entry)) {
        entry_count++;
    }
    
    fs_close(dir_file);
    
    // Only allow removal of empty directories
    if (entry_count > 2) {  // . and .. entries
        return -1;
    }
    
    return fs_delete_file(path);
}

// Create a symbolic link
int fs_symlink(const char* target, const char* link_path) {
    if (!target || !link_path) return -1;
    
    // Create symlink inode
    if (fs_create_file(link_path, FT_SYMLINK, FP_READ | FP_WRITE | FP_EXEC) < 0) {
        return -1;
    }
    
    // Get symlink inode
    uint32_t link_inode;
    if (fs_path_to_inode(link_path, &link_inode) < 0) return -1;
    
    struct inode* link = fs_get_inode(link_inode);
    if (!link) return -1;
    
    // Store target path
    strncpy(link->symlink_target, target, MAX_FILENAME - 1);
    link->symlink_target[MAX_FILENAME - 1] = '\0';
    
    return 0;
}

// Read symbolic link target
int fs_readlink(const char* path, char* buffer, size_t size) {
    if (!path || !buffer || size == 0) return -1;
    
    uint32_t link_inode;
    if (fs_path_to_inode(path, &link_inode) < 0) return -1;
    
    struct inode* link = fs_get_inode(link_inode);
    if (!link || link->type != FT_SYMLINK) return -1;
    
    size_t target_len = strlen(link->symlink_target);
    if (target_len >= size) return -1;
    
    strcpy(buffer, link->symlink_target);
    return target_len;
}

// Set file permissions
int fs_set_permissions(const char* path, uint32_t permissions) {
    if (!path) return -1;
    
    uint32_t inode_num;
    if (fs_path_to_inode(path, &inode_num) < 0) return -1;
    
    struct inode* inode = fs_get_inode(inode_num);
    if (!inode) return -1;
    
    // Check if user has permission to change permissions
    if (current_process && current_process->uid != ROOT_UID && current_process->uid != inode->uid) {
        return -1;
    }
    
    inode->permissions = permissions;
    return 0;
}

// Set file ownership
int fs_set_ownership(const char* path, uint32_t uid, uint32_t gid) {
    if (!path) return -1;
    
    uint32_t inode_num;
    if (fs_path_to_inode(path, &inode_num) < 0) return -1;
    
    struct inode* inode = fs_get_inode(inode_num);
    if (!inode) return -1;
    
    // Only root can change ownership
    if (current_process && current_process->uid != ROOT_UID) {
        return -1;
    }
    
    inode->uid = uid;
    inode->gid = gid;
    return 0;
}

// Initialize terminal management
int tty_init(void) {
    // Initialize first terminal
    struct device* tty = kmalloc(sizeof(struct device));
    if (!tty) return -1;
    
    tty->type = DEV_TTY;
    tty->major = next_major++;
    tty->minor = 0;
    tty->read = tty_read;
    tty->write = tty_write;
    tty->ioctl = tty_ioctl;
    
    if (dev_register(tty) < 0) {
        kfree(tty);
        return -1;
    }
    
    // Initialize terminal settings
    terminal_settings[0].c_iflag = 0;
    terminal_settings[0].c_oflag = TF_CRMOD;
    terminal_settings[0].c_cflag = 0;
    terminal_settings[0].c_lflag = TF_ECHO | TF_ICANON | TF_ISIG;
    
    // Initialize window size
    terminal_windows[0].ws_row = 25;
    terminal_windows[0].ws_col = 80;
    terminal_windows[0].ws_xpixel = 0;
    terminal_windows[0].ws_ypixel = 0;
    
    return 0;
}

// Terminal operations
int tty_open(struct device* dev) {
    if (!dev || dev->type != DEV_TTY) return -1;
    return 0;
}

int tty_close(struct device* dev) {
    if (!dev || dev->type != DEV_TTY) return -1;
    return 0;
}

int tty_read(struct device* dev, void* buffer, size_t size) {
    (void)size;  // Suppress unused parameter warning
    if (!dev || dev->type != DEV_TTY || !buffer) return -1;
    
    // For now, just read from keyboard
    // TODO: Implement proper keyboard input handling
    return 0;
}

int tty_write(struct device* dev, const void* buffer, size_t size) {
    if (!dev || dev->type != DEV_TTY || !buffer) return -1;
    
    // Write to video memory
    const char* str = buffer;
    for (size_t i = 0; i < size; i++) {
        putchar(str[i]);
    }
    return size;
}

int tty_ioctl(struct device* dev, int request, void* arg) {
    if (!dev || dev->type != DEV_TTY) return -1;
    
    switch (request) {
        case TCGETS:
            if (!arg) return -1;
            memcpy(arg, &terminal_settings[dev->minor], sizeof(struct termios));
            return 0;
            
        case TCSETS:
            if (!arg) return -1;
            memcpy(&terminal_settings[dev->minor], arg, sizeof(struct termios));
            return 0;
            
        case TIOCGPGRP:
            if (!arg) return -1;
            *(pid_t*)arg = terminal_groups[dev->minor];
            return 0;
            
        case TIOCSPGRP:
            if (!arg) return -1;
            terminal_groups[dev->minor] = *(pid_t*)arg;
            return 0;
            
        case TIOCGWINSZ:
            if (!arg) return -1;
            memcpy(arg, &terminal_windows[dev->minor], sizeof(struct winsize));
            return 0;
            
        case TIOCSWINSZ:
            if (!arg) return -1;
            memcpy(&terminal_windows[dev->minor], arg, sizeof(struct winsize));
            return 0;
            
        default:
            return -1;
    }
}

// Device management
int dev_register(struct device* dev) {
    if (!dev) return -1;
    
    // Find free slot
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!devices[i]) {
            devices[i] = dev;
            return 0;
        }
    }
    
    return -1;
}

struct device* dev_get(uint32_t major, uint32_t minor) {
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (devices[i] && devices[i]->major == major && devices[i]->minor == minor) {
            return devices[i];
        }
    }
    return 0;
}

int dev_read(struct device* dev, void* buffer, size_t size) {
    if (!dev || !dev->read) return -1;
    return dev->read(dev, buffer, size);
}

int dev_write(struct device* dev, const void* buffer, size_t size) {
    if (!dev || !dev->write) return -1;
    return dev->write(dev, buffer, size);
}

int dev_ioctl(struct device* dev, int request, void* arg) {
    if (!dev || !dev->ioctl) return -1;
    return dev->ioctl(dev, request, arg);
}

// File descriptor management
int fd_alloc(struct process* proc) {
    if (!proc) return -1;
    
    // Find free file descriptor
    for (int i = 0; i < MAX_FDS; i++) {
        if (!fd_table[i]) {
            struct file_descriptor* fd = kmalloc(sizeof(struct file_descriptor));
            if (!fd) return -1;
            
            fd->file = 0;
            fd->flags = 0;
            fd->pos = 0;
            fd->dev = 0;
            
            fd_table[i] = fd;
            return i;
        }
    }
    
    return -1;
}

void fd_free(struct process* proc, int fd) {
    (void)proc;  // Suppress unused parameter warning
    if (fd < 0 || fd >= MAX_FDS) return;
    
    struct file_descriptor* fd_entry = fd_table[fd];
    if (fd_entry) {
        if (fd_entry->file) {
            fs_close(fd_entry->file);
        }
        kfree(fd_entry);
        fd_table[fd] = 0;
    }
}

struct file_descriptor* fd_get(struct process* proc, int fd) {
    (void)proc;  // Suppress unused parameter warning
    if (fd < 0 || fd >= MAX_FDS) return 0;
    return fd_table[fd];
}

int fd_dup(struct process* proc, int oldfd) {
    struct file_descriptor* old = fd_get(proc, oldfd);
    if (!old) return -1;
    
    int newfd = fd_alloc(proc);
    if (newfd < 0) return -1;
    
    struct file_descriptor* new = fd_table[newfd];
    new->file = old->file;
    new->flags = old->flags;
    new->pos = old->pos;
    new->dev = old->dev;
    
    return newfd;
}

int fd_dup2(struct process* proc, int oldfd, int newfd) {
    struct file_descriptor* old = fd_get(proc, oldfd);
    if (!old) return -1;
    
    // If newfd is already open, close it
    if (newfd < MAX_FDS && fd_table[newfd]) {
        fd_free(proc, newfd);
    }
    
    // Allocate new file descriptor
    if (newfd >= MAX_FDS) {
        newfd = fd_alloc(proc);
        if (newfd < 0) return -1;
    }
    
    struct file_descriptor* new = fd_table[newfd];
    new->file = old->file;
    new->flags = old->flags;
    new->pos = old->pos;
    new->dev = old->dev;
    
    return newfd;
}

// Pipe operations
static int pipe_read(struct device* dev, void* buffer, size_t size) __attribute__((unused));
static int pipe_write(struct device* dev, const void* buffer, size_t size) __attribute__((unused));
static int pipe_ioctl(struct device* dev, int request, void* arg) __attribute__((unused));

static int pipe_read(struct device* dev, void* buffer, size_t size) {
    if (!dev || dev->type != DEV_PIPE || !buffer) return -1;
    
    struct pipe* pipe = dev->private_data;
    if (!pipe) return -1;
    
    size_t bytes_read = 0;
    
    while (bytes_read < size && pipe->count > 0) {
        size_t chunk = size - bytes_read;
        if (chunk > pipe->count) chunk = pipe->count;
        
        if (pipe->read_pos + chunk > PIPE_BUFFER_SIZE) {
            // Wrap around
            size_t first_part = PIPE_BUFFER_SIZE - pipe->read_pos;
            memcpy((char*)buffer + bytes_read, pipe->buffer + pipe->read_pos, first_part);
            memcpy((char*)buffer + bytes_read + first_part, pipe->buffer, chunk - first_part);
        } else {
            memcpy((char*)buffer + bytes_read, pipe->buffer + pipe->read_pos, chunk);
        }
        
        pipe->read_pos = (pipe->read_pos + chunk) % PIPE_BUFFER_SIZE;
        pipe->count -= chunk;
        bytes_read += chunk;
    }
    
    return bytes_read;
}

static int pipe_write(struct device* dev, const void* buffer, size_t size) {
    if (!dev || dev->type != DEV_PIPE || !buffer) return -1;
    
    struct pipe* pipe = dev->private_data;
    if (!pipe) return -1;
    
    size_t bytes_written = 0;
    
    while (bytes_written < size && pipe->count < PIPE_BUFFER_SIZE) {
        size_t chunk = size - bytes_written;
        if (chunk > PIPE_BUFFER_SIZE - pipe->count) {
            chunk = PIPE_BUFFER_SIZE - pipe->count;
        }
        
        if (pipe->write_pos + chunk > PIPE_BUFFER_SIZE) {
            // Wrap around
            size_t first_part = PIPE_BUFFER_SIZE - pipe->write_pos;
            memcpy(pipe->buffer + pipe->write_pos, (char*)buffer + bytes_written, first_part);
            memcpy(pipe->buffer, (char*)buffer + bytes_written + first_part, chunk - first_part);
        } else {
            memcpy(pipe->buffer + pipe->write_pos, (char*)buffer + bytes_written, chunk);
        }
        
        pipe->write_pos = (pipe->write_pos + chunk) % PIPE_BUFFER_SIZE;
        pipe->count += chunk;
        bytes_written += chunk;
    }
    
    return bytes_written;
}

static int pipe_ioctl(struct device* dev, int request, void* arg) {
    if (!dev || dev->type != DEV_PIPE) return -1;
    
    struct pipe* pipe = dev->private_data;
    if (!pipe) return -1;
    
    switch (request) {
        case FIONREAD:  // Get number of bytes available to read
            if (!arg) return -1;
            *(int*)arg = pipe->count;
            return 0;
            
        case FIONWRITE:  // Get number of bytes that can be written
            if (!arg) return -1;
            *(int*)arg = PIPE_BUFFER_SIZE - pipe->count;
            return 0;
            
        default:
            return -1;
    }
} 