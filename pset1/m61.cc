#define M61_DISABLE 1
#include "m61.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <limits.h>
#include <cstddef>
#include <unordered_set>
#include <unordered_map>
#include <string>

// STATS

unsigned long malloc_calls = 0;
unsigned long free_calls = 0;

unsigned long assigned_bytes = 0;
unsigned long freed_bytes = 0;

unsigned long failed_mallocs = 0;
unsigned long failed_malloc_bytes = 0;

uintptr_t heap_min;
uintptr_t heap_max;

struct meta_data
{
    size_t sz;
    const char *file;
    long line;
};
// Making sure that the META_DATA_SIZE is a multiple of alignof(std::max_align_t)
unsigned const long META_DATA_SIZE = (((sizeof(struct meta_data) - 1) / alignof(std::max_align_t)) + 1) * alignof(std::max_align_t);

std::unordered_set<meta_data *>
    alloced_meta_data_ptrs;
std::unordered_set<meta_data *> freed_meta_data_ptrs;

struct malloc_call
{
    const char *file;
    long line;

    bool operator==(const malloc_call &malloc_call) const
    {
        return this->file == malloc_call.file && this->line == malloc_call.line;
    }
};
namespace std
{
    template <>
    struct std::hash<malloc_call>
    {
        size_t operator()(const malloc_call &malloc_call) const
        {
            std::hash<const char *> file_hash;
            return (file_hash(malloc_call.file) + malloc_call.line);
        }
    };
} // namespace std
std::unordered_map<malloc_call, size_t> all_malloc_calls;

/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void *m61_malloc(size_t sz, const char *file, long line)
{
    (void)file, (void)line; // avoid uninitialized variable warnings
                            // Your code here.
    float load_factor = 0.3;
    alloced_meta_data_ptrs.max_load_factor(load_factor);
    freed_meta_data_ptrs.max_load_factor(load_factor);
    all_malloc_calls.max_load_factor(load_factor);
    meta_data meta_data = {.sz = sz, .file = file, .line = line};
    size_t real_sz = sz + META_DATA_SIZE;
    void *ptr = base_malloc(real_sz);
    uintptr_t uint_ptr = (uintptr_t)ptr;
    if (ptr == nullptr || (size_t)-sz <= META_DATA_SIZE)
    {
        failed_mallocs++;
        failed_malloc_bytes += sz;
        return nullptr;
    }
    uintptr_t min_ptr = uint_ptr;
    uintptr_t max_ptr = uint_ptr + real_sz;
    if (malloc_calls == 0)
    {
        heap_min = min_ptr;
        heap_max = max_ptr;
    }
    else
    {
        heap_min = min_ptr < heap_min ? min_ptr : heap_min;
        heap_max = max_ptr > heap_max ? max_ptr : heap_max;
    }
    malloc_calls++;
    assigned_bytes += sz;
    struct meta_data *meta_data_ptr = (struct meta_data *)ptr;
    // For some really shocking reason, if I pass meta_data_ptr instead of &meta_data, it takes at least 10x longer
    alloced_meta_data_ptrs.insert(meta_data_ptr);
    *meta_data_ptr = meta_data;
    freed_meta_data_ptrs.erase(meta_data_ptr);
    struct malloc_call malloc_call = {.file = file, .line = line};
    if (all_malloc_calls.find(malloc_call) == all_malloc_calls.end())
    {
        all_malloc_calls.insert({malloc_call, 1});
    }
    else
    {
        size_t new_val = all_malloc_calls.at(malloc_call) + 1;
        all_malloc_calls.erase(malloc_call);
        all_malloc_calls.insert({malloc_call, new_val});
    }
    //printf("load factor: %fu\n", alloced_meta_data_ptrs.load_factor());
    return (void *)(uint_ptr + META_DATA_SIZE);
}

/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void check_if_in_allocated_block(uintptr_t ptr, const char *file, long line)
{
    std::unordered_set<meta_data *>::iterator itr;
    for (itr = alloced_meta_data_ptrs.begin(); itr != alloced_meta_data_ptrs.end(); itr++)
    {
        if (freed_meta_data_ptrs.find(*itr) == freed_meta_data_ptrs.end())
        {
            uintptr_t start_ptr = (uintptr_t)*itr;
            uintptr_t end_ptr = start_ptr + (**itr).sz;
            if (end_ptr > ptr && ptr > start_ptr)
            {
                printf("%s:%lu: %p is %lu bytes inside a %lu byte region allocated here\n", file, line, (void *)ptr, (unsigned long)ptr - start_ptr, (unsigned long)end_ptr - start_ptr);
            }
        }
    }
}

void m61_free(void *ptr, const char *file, long line)
{
    (void)file, (void)line; // avoid uninitialized variable warnings
    // Your code here.
    if (ptr == nullptr)
    {
        return;
    }
    struct meta_data *meta_data_ptr = (struct meta_data *)((uintptr_t)ptr - META_DATA_SIZE);
    bool out_of_heap = heap_min > (uintptr_t)meta_data_ptr || (uintptr_t)meta_data_ptr > heap_max;
    //printf("alloc len: %lu\n", alloced_meta_data_ptrs.size());
    bool not_allocated = alloced_meta_data_ptrs.find(meta_data_ptr) == alloced_meta_data_ptrs.end();
    bool already_freed = freed_meta_data_ptrs.find(meta_data_ptr) != freed_meta_data_ptrs.end();
    if (out_of_heap || not_allocated || already_freed)
    {
        const char *reason = out_of_heap ? "not in heap" : (not_allocated ? "not allocated" : "double free");
        printf("MEMORY BUG: %s:%lu: invalid free of pointer %p, %s\n", file, line, ptr, reason);
        if (not_allocated)
        {
            check_if_in_allocated_block((uintptr_t)ptr, file, line);
        }
        exit(0);
    }
    else
    {
        // We need some error handling here
        struct meta_data meta_data = *meta_data_ptr;
        free_calls++;
        freed_bytes += meta_data.sz;
        freed_meta_data_ptrs.insert(meta_data_ptr);
        //printf("Is nullptr?: %d\n", meta_data_ptr == nullptr);
        base_free(meta_data_ptr);
    }
}

/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void *m61_calloc(size_t nmemb, size_t sz, const char *file, long line)
{
    // Your code here (to fix test014).
    size_t full_size = (((size_t)-1 / sz) > nmemb) ? nmemb * sz : (size_t)-1;
    void *ptr = m61_malloc(full_size, file, line);
    if (ptr != nullptr)
    {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}

/// m61_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_get_statistics(m61_statistics *stats)
{
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(m61_statistics));
    // Your code here.
    stats->nactive = malloc_calls - free_calls;
    stats->active_size = assigned_bytes - freed_bytes;
    stats->ntotal = malloc_calls;
    stats->total_size = assigned_bytes;
    stats->nfail = failed_mallocs;
    stats->fail_size = failed_malloc_bytes;
    stats->heap_min = heap_min;
    stats->heap_max = heap_max;
}

/// m61_print_statistics()
///    Print the current memory statistics.

void m61_print_statistics()
{
    m61_statistics stats;
    m61_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

/// m61_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void print_singular_leak_report(meta_data *meta_data_ptr)
{
    void *data_ptr = (void *)(((uintptr_t)meta_data_ptr) + META_DATA_SIZE);
    meta_data meta_data = *meta_data_ptr;
    printf("LEAK CHECK: %s:%lu: allocated object %p with size %lu\n", meta_data.file, meta_data.line, data_ptr, meta_data.sz);
}

void m61_print_leak_report()
{
    for (std::unordered_set<meta_data *>::iterator itr = alloced_meta_data_ptrs.begin(); itr != alloced_meta_data_ptrs.end(); itr++)
    {
        if (freed_meta_data_ptrs.find(*itr) == freed_meta_data_ptrs.end())
        {
            print_singular_leak_report(*itr);
        }
    }
}
/// m61_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

float HEAVY_CUTOFF = 0.1;
void m61_print_heavy_hitter_report()
{
    for (std::unordered_map<malloc_call, size_t>::iterator itr = all_malloc_calls.begin(); itr != all_malloc_calls.end(); itr++)
    {
        const char *file = (*itr).first.file;
        long line = (*itr).first.line;
        size_t num_calls = (*itr).second;
        double perc = num_calls * 1.0 / malloc_calls;
        if (perc > HEAVY_CUTOFF)
        {
            printf("HEAVY HITTER: %s:%lu: %lu bytes (%g%%)\n", file, line, num_calls, perc * 100);
        }
    }
}
