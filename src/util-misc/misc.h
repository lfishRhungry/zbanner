#ifndef MISC_H
#define MISC_H

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
#define UNUSEDPARM(x) (void)x
#endif

#ifndef max
#define max(a, b)                                                              \
    ({                                                                         \
        typeof(a) _a = (a);                                                    \
        typeof(b) _b = (b);                                                    \
        _a > _b ? _a : _b;                                                     \
    })
#endif
#ifndef min
#define min(a, b)                                                              \
    ({                                                                         \
        typeof(a) _a = (a);                                                    \
        typeof(b) _b = (b);                                                    \
        _a < _b ? _a : _b;                                                     \
    })
#endif

#endif
