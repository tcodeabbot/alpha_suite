#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define GUARD_SIZE 16
#define GUARD_PATTERN 0xAB
#define FREED_PATTERN 0xDD
#define MAX_ALLOCATIONS 1024

typedef struct {
    size_t size;
    const char* file;
    int line;
    int is_freed;
    const char* func_name;          // Track which function allocated
    unsigned char guard_start[GUARD_SIZE];
} header_t;

static void* allocation_table[MAX_ALLOCATIONS] = {0};

/* ===============================
   Allocation Tracking Functions
=================================*/
void track_allocation(void* ptr) {
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocation_table[i] == NULL) {
            allocation_table[i] = ptr;
            return;
        }
    }
    printf("Allocation table full!\n");
    exit(1);
}

void untrack_allocation(void* ptr) {
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocation_table[i] == ptr) {
            allocation_table[i] = NULL;
            return;
        }
    }
    printf("Attempted to free untracked pointer!\n");
    exit(1);
}

int is_tracked(void* ptr) {
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocation_table[i] == ptr)
            return 1;
    }
    return 0;
}

/* ===============================
   Safe malloc
=================================*/
void* safe_malloc_debug(size_t size, const char* file, int line, const char* func_name) {
    size_t total_size = sizeof(header_t) + size + GUARD_SIZE;
    unsigned char* raw = (unsigned char*)malloc(total_size);
    if (!raw) return NULL;

    header_t* header = (header_t*)raw;
    header->size = size;
    header->file = file;
    header->line = line;
    header->is_freed = 0;
    header->func_name = func_name;

    memset(header->guard_start, GUARD_PATTERN, GUARD_SIZE);

    unsigned char* user_ptr = raw + sizeof(header_t);
    memset(user_ptr, 0, size);
    memset(user_ptr + size, GUARD_PATTERN, GUARD_SIZE);

    track_allocation(user_ptr);
    return user_ptr;
}

/* ===============================
   Overflow Check
=================================*/
void check_overflow(void* ptr) {
    if (!is_tracked(ptr)) {
        printf("ERROR: Pointer not tracked!\n");
        exit(1);
    }

    header_t* header = (header_t*)((unsigned char*)ptr - sizeof(header_t));
    unsigned char* user_ptr = (unsigned char*)ptr;

    if (header->is_freed) {
        printf("ERROR: Use-after-free detected in function %s!\n", header->func_name);
        printf("Originally allocated at %s:%d\n", header->file, header->line);
        exit(1);
    }

    for (int i = 0; i < GUARD_SIZE; i++) {
        if (header->guard_start[i] != GUARD_PATTERN) {
            printf("BUFFER UNDERFLOW detected in function %s!\n", header->func_name);
            printf("Allocation site: %s:%d\n", header->file, header->line);
            exit(1);
        }
    }

    for (int i = 0; i < GUARD_SIZE; i++) {
        if (user_ptr[header->size + i] != GUARD_PATTERN) {
            printf("BUFFER OVERFLOW detected in function %s!\n", header->func_name);
            printf("Allocation site: %s:%d\n", header->file, header->line);
            exit(1);
        }
    }
}

/* ===============================
   Safe free
=================================*/
void safe_free_debug(void* ptr, const char* file, int line, const char* func_name) {
    if (!ptr) return;

    if (!is_tracked(ptr)) {
        printf("DOUBLE FREE or invalid free detected in function %s at %s:%d\n",
               func_name, file, line);
        exit(1);
    }

    check_overflow(ptr);

    header_t* header = (header_t*)((unsigned char*)ptr - sizeof(header_t));
    header->is_freed = 1;
    memset(ptr, FREED_PATTERN, header->size);

    untrack_allocation(ptr);
    free((unsigned char*)ptr - sizeof(header_t));
}

/* ===============================
   Leak Detection
=================================*/
void check_memory_leaks() {
    int leaks = 0;
    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        if (allocation_table[i] != NULL) {
            header_t* header = (header_t*)((unsigned char*)allocation_table[i] - sizeof(header_t));
            printf("MEMORY LEAK: %zu bytes in function %s, allocated at %s:%d\n",
                   header->size, header->func_name, header->file, header->line);
            leaks++;
        }
    }
    if (leaks == 0)
        printf("No memory leaks detected.\n");
}

/* ===============================
   Macro Overrides
=================================*/
#define malloc(x) safe_malloc_debug(x, __FILE__, __LINE__, __func__)
#define free(x) safe_free_debug(x, __FILE__, __LINE__, __func__)

/* ===============================
   Function Testing Harness
=================================*/
void test_function(void (*func)(void)) {
    printf("\n=== Testing function: %s ===\n", __func__);
    func();
    check_memory_leaks();
}

/* ===============================
   Example Functions
=================================*/
void vulnerable_function() {
    char* buf = malloc(10);
    strcpy(buf, "This string is definitely too long"); // intentional overflow
    free(buf);
}

void safe_function() {
    char* buf = malloc(20);
    strcpy(buf, "safe");
    free(buf);
}

/* ===============================
   Main
=================================*/
int main() {
    test_function(vulnerable_function);
    test_function(safe_function);

    return 0;
}
