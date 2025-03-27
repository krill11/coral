#include "memory.h"
#include <stddef.h>

// Current page directory
static page_directory_t current_directory = 0;

// Kernel heap start
static struct memory_block* heap_start = 0;

// Initialize paging
static void init_paging(void) {
    // Create a new page directory
    current_directory = (page_directory_t)get_page();
    
    // Clear the page directory
    for (int i = 0; i < 1024; i++) {
        current_directory[i] = 0;
    }
    
    // Map kernel space
    for (uint32_t addr = KERNEL_START; addr < KERNEL_END; addr += PAGE_SIZE) {
        void* page = get_page();
        map_page(page, (void*)addr, PAGE_PRESENT | PAGE_RW);
    }
    
    // Enable paging
    __asm__ volatile("movl %0, %%cr3" : : "r"(current_directory));
    uint32_t cr0;
    __asm__ volatile("movl %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000;
    __asm__ volatile("movl %0, %%cr0" : : "r"(cr0));
}

// Initialize memory management
void mm_init(void) {
    // Initialize paging
    init_paging();
    
    // Initialize kernel heap
    heap_start = (struct memory_block*)KERNEL_START;
    heap_start->size = KERNEL_END - KERNEL_START - sizeof(struct memory_block);
    heap_start->next = 0;
    heap_start->free = 1;
}

// Allocate a page
void* get_page(void) {
    static uint32_t next_page = KERNEL_END;
    void* page = (void*)next_page;
    next_page += PAGE_SIZE;
    return page;
}

// Free a page
void free_page(void* page) {
    (void)page;  // Suppress unused parameter warning
    // For now, we don't actually free pages
    // This will be implemented when we add page frame allocation
}

// Map a page
void map_page(void* phys_addr, void* virt_addr, uint32_t flags) {
    uint32_t pd_index = (uint32_t)virt_addr >> 22;
    uint32_t pt_index = (uint32_t)virt_addr >> 12 & 0x3FF;
    
    // Get or create page table
    uint32_t table_entry = (uint32_t)current_directory[pd_index];
    if (!(table_entry & PAGE_PRESENT)) {
        page_table_t table = (page_table_t)get_page();
        current_directory[pd_index] = (page_t)((uint32_t)table | PAGE_PRESENT | PAGE_RW | PAGE_USER);
        
        // Clear the page table
        for (int i = 0; i < 1024; i++) {
            table[i] = 0;
        }
        
        // Map the page
        table[pt_index] = (page_t)((uint32_t)phys_addr | flags);
    } else {
        page_table_t table = (page_table_t)(table_entry & PAGE_MASK);
        table[pt_index] = (page_t)((uint32_t)phys_addr | flags);
    }
}

// Unmap a page
void unmap_page(void* virt_addr) {
    uint32_t pd_index = (uint32_t)virt_addr >> 22;
    uint32_t pt_index = (uint32_t)virt_addr >> 12 & 0x3FF;
    
    uint32_t table_entry = (uint32_t)current_directory[pd_index];
    if (table_entry & PAGE_PRESENT) {
        page_table_t table = (page_table_t)(table_entry & PAGE_MASK);
        table[pt_index] = 0;
    }
}

// Kernel memory allocation
void* kmalloc(size_t size) {
    struct memory_block* block = heap_start;
    
    // Align size to 4 bytes
    size = (size + 3) & ~3;
    
    // Find a free block that's big enough
    while (block) {
        if (block->free && block->size >= size) {
            // If the block is much larger than needed, split it
            if (block->size >= size + sizeof(struct memory_block) + 4) {
                struct memory_block* new_block = (struct memory_block*)((char*)block + sizeof(struct memory_block) + size);
                new_block->size = block->size - size - sizeof(struct memory_block);
                new_block->next = block->next;
                new_block->free = 1;
                
                block->size = size;
                block->next = new_block;
            }
            
            block->free = 0;
            return (void*)((char*)block + sizeof(struct memory_block));
        }
        
        block = block->next;
    }
    
    return 0; // No suitable block found
}

// Kernel memory deallocation
void kfree(void* ptr) {
    if (!ptr) return;
    
    struct memory_block* block = (struct memory_block*)((char*)ptr - sizeof(struct memory_block));
    block->free = 1;
    
    // Try to merge with next block if it's free
    while (block->next && block->next->free) {
        block->size += sizeof(struct memory_block) + block->next->size;
        block->next = block->next->next;
    }
} 