#ifndef _MEMORY_H
#define _MEMORY_H

#include <stdint.h>

// Page size is 4KB
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE - 1))

// Page table entry flags
#define PAGE_PRESENT    0x001
#define PAGE_RW        0x002
#define PAGE_USER      0x004
#define PAGE_ACCESSED  0x020
#define PAGE_DIRTY     0x040

// Memory regions
#define KERNEL_START 0x100000
#define KERNEL_END   0x200000

// Memory management functions
void mm_init(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* get_page(void);
void free_page(void* page);
void map_page(void* phys_addr, void* virt_addr, uint32_t flags);
void unmap_page(void* virt_addr);

// Page directory and table structures
typedef uint32_t page_t;
typedef page_t* page_table_t;
typedef page_table_t* page_directory_t;

// Memory management structures
struct memory_block {
    size_t size;
    struct memory_block* next;
    int free;
};

#endif // _MEMORY_H 