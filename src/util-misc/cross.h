#ifndef MISC_H

// inline
#if defined(_MSC_VER)
#define inline _inline
#endif

// bool
#if _MSC_VER && _MSC_VER < 1800
typedef enum { false = 0, true = 1 } bool;
#else
#include <stdbool.h>
#endif

// MAX MIN
#if defined(__GNUC__)
#define max(a, b)                                                              \
  ({                                                                           \
    typeof(a) _a = (a);                                                        \
    typeof(b) _b = (b);                                                        \
    _a > _b ? _a : _b;                                                         \
  })
#define min(a, b)                                                              \
  ({                                                                           \
    typeof(a) _a = (a);                                                        \
    typeof(b) _b = (b);                                                        \
    _a < _b ? _a : _b;                                                         \
  })
#endif

// ARRAY
#if defined(_MSC_VER)
#include <stdlib.h>
#define ARRAY_SIZE(arr) (_countof((arr)))
#elif defined(__GNUC__)
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int : -!!(e); }))
#define __must_be_array(a)                                                     \
  BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#else
#warning unknown compiler
#endif

// unused
#if defined(_MSC_VER)
#define UNUSEDPARM(x) x
#elif defined(__GNUC__)
#define UNUSEDPARM(x) (void) x
#endif

#endif

