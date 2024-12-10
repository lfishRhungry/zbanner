#ifndef PORT_THREADS_H
#define PORT_THREADS_H
#include <stdio.h>
#include <stdint.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include <stdbool.h>

/**
 * Returns the number of CPUs in the system, including virtual CPUs.
 * On a single processor system, the number returned will be '1'.
 * On a dual socket, dual-core per socket, hyperthreaded system, the
 * count will be '8'.
 */
unsigned pixie_cpu_get_count(void);
void     pixie_cpu_set_affinity(unsigned processor);
void     pixie_cpu_raise_priority(void);
/**
 * Launch and Join
 */
size_t   pixie_begin_thread(void (*worker_thread)(void *), unsigned flags,
                            void *worker_data);
void     pixie_thread_join(size_t thread_handle);
/**
 * set a name for the thread.
 * NOTE: name length cannot exceed 16 with null tail on Linux.
 */
void     pixie_set_thread_name(const char *name);
/* barrier */
void    *pixie_create_barrier(unsigned total_threads);
void     pixie_wait_barrier(void *p_barrier);
bool     pixie_delete_barrier(void *p_barrier);
/* rwlock */
void    *pixie_create_rwlock();
void     pixie_acquire_rwlock_read(void *p_rwlock);
void     pixie_release_rwlock_read(void *p_rwlock);
void     pixie_acquire_rwlock_write(void *p_rwlock);
void     pixie_release_rwlock_write(void *p_rwlock);
bool     pixie_delete_rwlock(void *p_rwlock);
/* mutex */
void    *pixie_create_mutex();
void     pixie_acquire_mutex(void *p_mutex);
void     pixie_release_mutex(void *p_mutex);
bool     pixie_delete_mutex(void *p_mutex);

/**
 * !NOTE: Do not use
 */
#if defined(_MSC_VER)
#define pixie_locked_add_u32(dst, src)                                         \
    (void)_InterlockedExchangeAdd((volatile long *)(dst), (src))
#define pixie_locked_add_u64(dst, src)                                         \
    (void)_InterlockedExchangeAdd64((volatile __int64 *)(dst), (src))
#define pixie_locked_cas_u32(dst, src, expected)                               \
    (_InterlockedCompareExchange((volatile long *)dst, src, expected) ==       \
     (expected))
#define pixie_locked_cas_u64(dst, src, expected)                               \
    (_InterlockedCompareExchange64((volatile long long *)dst, src,             \
                                   expected) == (expected))

#elif defined(__GNUC__)
#define pixie_locked_add_u32(dst, src)                                         \
    (void)__sync_add_and_fetch((volatile int *)(dst), (int)(src))
#define pixie_locked_add_u64(dst, src)                                         \
    (void)__sync_add_and_fetch((volatile long long *)(dst), (long long)(src))
#define pixie_locked_cas_u32(dst, src, expected)                               \
    __sync_bool_compare_and_swap((volatile int *)(dst), (int)expected, (int)src)
#define pixie_locked_cas_u64(dst, src, expected)                               \
    __sync_bool_compare_and_swap((volatile long long int *)(dst),              \
                                 (long long int)expected, (long long int)src)
#else
#warning unknown compiler
#endif

static inline bool pixie_locked_cas_float(volatile float *dst, float src,
                                          float expected) {
    return pixie_locked_cas_u32((uint32_t *)dst, (uint32_t)src,
                                (uint32_t)expected);
}

static inline bool pixie_locked_cas_double(volatile double *dst, double src,
                                           double expected) {
    return pixie_locked_cas_u64((uint64_t *)dst, (uint64_t)src,
                                (uint64_t)expected);
}

static inline void pixie_locked_add_float(volatile float *dst, float src) {
    pixie_locked_add_u32((uint32_t *)dst, (uint32_t)src);
}

static inline void pixie_locked_add_double(volatile double *dst, double src) {
    pixie_locked_add_u64((uint64_t *)dst, (uint64_t)src);
}

static inline uint32_t pixie_locked_fetch_u32(volatile uint32_t *dst) {
#if defined(_MSC_VER)
    return _InterlockedExchangeAdd(dst, 0);
#elif defined(__GNUC__)
    return __sync_add_and_fetch(dst, 0);
#else
#warning unknown compiler
    return 0;
#endif
}

static inline uint64_t pixie_locked_fetch_u64(volatile uint64_t *dst) {
#if defined(_MSC_VER)
    return _InterlockedExchangeAdd64(dst, 0);
#elif defined(__GNUC__)
    return __sync_add_and_fetch(dst, 0);
#else
#warning unknown compiler
    return 0;
#endif
}

static inline float pixie_locked_fetch_float(volatile float *dst) {
    return (float)pixie_locked_fetch_u32((uint32_t *)dst);
}

static inline double pixie_locked_fetch_double(volatile double *dst) {
    return (double)pixie_locked_fetch_u64((uint64_t *)dst);
}

static inline void pixie_locked_store_u32(volatile uint32_t *old,
                                          uint32_t new) {
    while (!pixie_locked_cas_u32(old, new, pixie_locked_fetch_u32(old))) {
    }
}

static inline void pixie_locked_store_u64(volatile uint64_t *old,
                                          uint64_t new) {
    while (!pixie_locked_cas_u64(old, new, pixie_locked_fetch_u64(old))) {
    }
}

static inline void pixie_locked_store_float(volatile float *old, float new) {
    pixie_locked_store_u32((uint32_t *)old, (uint32_t) new);
}

static inline void pixie_locked_store_double(volatile double *old, float new) {
    pixie_locked_store_u64((uint64_t *)old, (uint64_t) new);
}

#endif
