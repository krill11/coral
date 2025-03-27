#ifndef _FS_H
#define _FS_H

#include <stdint.h>

// File types
#define FT_FILE     0
#define FT_DIR      1
#define FT_DEVICE   2
#define FT_SYMLINK  3

// File permissions
#define FP_READ     0x4
#define FP_WRITE    0x2
#define FP_EXEC     0x1

// File flags
#define FF_OPEN     0x1
#define FF_CREATE   0x2
#define FF_TRUNC    0x4
#define FF_APPEND   0x8

// Device types
#define DEV_TTY     0
#define DEV_PIPE    1

// File descriptor flags
#define FD_CLOEXEC  0x1
#define FD_NONBLOCK 0x2

// Terminal control commands
#define TCGETS      0x5401
#define TCSETS      0x5402
#define TCSETSW     0x5403
#define TCSETSF     0x5404
#define TIOCGPGRP   0x540F
#define TIOCSPGRP   0x5410
#define TIOCSTI     0x5412
#define TIOCGWINSZ  0x5413
#define TIOCSWINSZ  0x5414

// Terminal flags
#define TF_ECHO     0x1
#define TF_ICANON   0x2
#define TF_ISIG     0x4
#define TF_CRMOD    0x8

// Terminal structure
struct termios {
    uint32_t c_iflag;  // Input flags
    uint32_t c_oflag;  // Output flags
    uint32_t c_cflag;  // Control flags
    uint32_t c_lflag;  // Local flags
    uint8_t c_cc[32];  // Control characters
};

// Terminal window size
struct winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

// Device structure
struct device {
    uint32_t type;
    uint32_t major;
    uint32_t minor;
    void* private_data;
    int (*read)(struct device* dev, void* buffer, size_t size);
    int (*write)(struct device* dev, const void* buffer, size_t size);
    int (*ioctl)(struct device* dev, int request, void* arg);
};

// File descriptor structure
struct file_descriptor {
    struct file* file;
    uint32_t flags;
    size_t pos;
    struct device* dev;
};

// User and group IDs
#define ROOT_UID    0
#define ROOT_GID    0

// Directory entry structure
#define MAX_FILENAME 255
struct dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[MAX_FILENAME];
};

// File structure
struct file {
    uint32_t inode;
    uint32_t size;
    uint32_t type;
    uint32_t permissions;
    uint32_t flags;
    uint32_t ref_count;
    size_t pos;  // Current file position
    struct file* next;
};

// Inode structure
struct inode {
    uint32_t inode_num;
    uint32_t size;
    uint32_t type;
    uint32_t permissions;
    uint32_t uid;        // User ID
    uint32_t gid;        // Group ID
    uint32_t block_count;
    uint32_t blocks[12];  // Direct blocks
    uint32_t indirect;    // Indirect block
    uint32_t double_indirect;  // Double indirect block
    char symlink_target[MAX_FILENAME];  // For symbolic links
};

// Filesystem functions
void fs_init(void);
struct file* fs_open(const char* path, uint32_t flags);
int fs_close(struct file* file);
int fs_read(struct file* file, void* buffer, size_t size, size_t offset);
int fs_write(struct file* file, const void* buffer, size_t size, size_t offset);
int fs_executable_load(const char* path, void** entry_point, void** stack_top);

// Directory functions
int fs_readdir(struct file* dir, struct dir_entry* entry);
int fs_mkdir(const char* path);
int fs_rmdir(const char* path);

// File management functions
int fs_create_file(const char* path, uint32_t type, uint32_t permissions);
int fs_delete_file(const char* path);
int fs_symlink(const char* target, const char* link_path);
int fs_readlink(const char* path, char* buffer, size_t size);

// Helper functions
struct inode* fs_get_inode(uint32_t inode_num);
int fs_path_to_inode(const char* path, uint32_t* inode_num);
int fs_check_permissions(struct file* file, uint32_t required);
int fs_set_permissions(const char* path, uint32_t permissions);
int fs_set_ownership(const char* path, uint32_t uid, uint32_t gid);

// Block management
#define BLOCK_SIZE 4096
void* fs_get_block(uint32_t block_num);
void fs_free_block(uint32_t block_num);
int fs_allocate_blocks(struct inode* inode, uint32_t num_blocks);

// File descriptor management
int fd_alloc(struct process* proc);
void fd_free(struct process* proc, int fd);
struct file_descriptor* fd_get(struct process* proc, int fd);
int fd_dup(struct process* proc, int oldfd);
int fd_dup2(struct process* proc, int oldfd, int newfd);

// Device management
int dev_register(struct device* dev);
struct device* dev_get(uint32_t major, uint32_t minor);
int dev_read(struct device* dev, void* buffer, size_t size);
int dev_write(struct device* dev, const void* buffer, size_t size);
int dev_ioctl(struct device* dev, int request, void* arg);

// Terminal management
int tty_init(void);
int tty_open(struct device* dev);
int tty_close(struct device* dev);
int tty_read(struct device* dev, void* buffer, size_t size);
int tty_write(struct device* dev, const void* buffer, size_t size);
int tty_ioctl(struct device* dev, int request, void* arg);

#endif // _FS_H