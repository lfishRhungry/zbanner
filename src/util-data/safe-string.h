/*
    This is an addition for safe "string" functions of Robert Graham

    This is for the "safe" clib functions, where things like "strcpy()" is
    replaced with a safer version of the function, like "safe_strcpy()".
 
    NOTE: I tried to based these on Microosft's `..._s()` functions proposed
    in Annex K, but it's become too hard trying to deal with both my own
    version and existing versions. Therefore, I've changed this code to
    use names not used by others.

 Reference:
 http://msdn.microsoft.com/en-us/library/bb288454.aspx
*/
#ifndef SAFE_STRING_H
#define SAFE_STRING_H
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _MSC_VER
#pragma warning(disable: 4996)
#endif

#if defined(WIN32)
#define strncasecmp _strnicmp
#endif

#undef strcpy
#define strcpy      STRCPY_FUNCTION_IS_BAD

/*#undef strncpy
#define strncpy     STRNCPY_FUNCTION_IS_BAD*/

#undef strcat
#define strcat      STRCAT_FUNCTION_IS_BAD

#undef strncat
#define strncat     STRNCAT_FUNCTION_IS_BAD

#undef sprintf
#define sprintf     SPRINTF_FUNCTION_IS_BAD

#undef vsprintf
#define vsprintf    VSPRINTF_FUNCTION_IS_BAD

#undef strtok
#define strtok      STRTOK_FUNCTION_IS_BAD

#undef gets
#define gets        GETS_FUNCTION_IS_BAD

#undef scanf
#define scanf       SCANF_FUNCTION_IS_BAD

#undef sscanf
#define sscanf      SSCANF_FUNCTION_IS_BAD

#undef itoa
#define itoa        ITOA_FUNCTION_IS_BAD

/**
 * A bounds checking version of strcpy, like `strcpy_s()` on Windows or
 * `strlcpy()` in glibc.
 */
void safe_strcpy(char *dst, size_t sizeof_dst, const char *src);
int safe_localtime(struct tm* _tm, const time_t *time);
int safe_gmtime(struct tm* _tm, const time_t *time);

/*`strstr` but in case insensitive*/
char * stristr (const char * haystack, const char * needle);


#if defined(_MSC_VER) && (_MSC_VER >= 1900)
/*Visual Studio 2015 and 2017*/
# include <stdio.h>
# include <string.h>
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# ifndef PRIu64
#  define PRIu64 "llu"
#  define PRId64 "lld"
#  define PRIx64 "llx"
# endif

#elif defined(_MSC_VER) && (_MSC_VER == 1600)
/*Visual Studio 2010*/
# include <stdio.h>
# include <string.h>
#pragma warning(disable: 4996)
#define snprintf _snprintf
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# ifndef PRIu64
#  define PRIu64 "llu"
#  define PRId64 "lld"
#  define PRIx64 "llx"
# endif


#elif defined(_MSC_VER) && (_MSC_VER == 1200)
/* Visual Studio 6.0 */
# define snprintf      _snprintf
# define strcasecmp     _stricmp
# define memcasecmp     _memicmp
# define vsnprintf     _vsnprintf

#elif defined(__GNUC__) && (__GNUC__ >= 4)
#include <inttypes.h>
 int memcasecmp(const void *lhs, const void *rhs, size_t length);;

#else
# warning unknown compiler
#endif


/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
void
trim(char *line, size_t sizeof_line);

/*****************************************************************************
 * Remove bad characters from the banner, especially new lines and HTML
 * control codes.
 *****************************************************************************/
const char *
normalize_string(const unsigned char *px, size_t length,
    char *buf, size_t buf_len);

/*****************************************************************************
 * os undependant memmem
 *****************************************************************************/
void *
safe_memmem(const void *src,int srclen,const void *trg,int trglen);

/*`memmem` but in case insensitive*/
void *
safe_memismem (const void * haystack, size_t haystacklen,
    const void * needle, size_t needlelen);

/**
 * Do a memmove() of a chunk of memory within a buffer with bounds checking.
 */
void
safe_memmove(unsigned char *buf, size_t length, size_t to, size_t from, size_t chunklength);

/**
 * Do a memset() of a chunk of memory within a buffer with bounds checking
 */
void
safe_memset(unsigned char *buf, size_t length, size_t offset, int c, size_t chunklength);

/**
 * is byt the header of src
*/
int
bytes_header(const void *src, size_t src_len, const void *byt, size_t byt_len);

/**
 * Transfer C string to argc argv.
 * Could handle quotes(ignore single quotes).
 * Argv should be freed.
*/
char** string_to_args(char *string, int *arg_count);

/**
 * Transfer C string to argc argv.
 * just handle  single quotes(ignore double quotes).
 * Argv should be freed.
*/
char** substring_to_args(char *substring, int *arg_count);

int
name_equals(const char *lhs, const char *rhs);

uint64_t
parseIntBytes(const void *vstr, size_t length);

/**
 * @param format_time buffer to save time str at least 32 bytes.
 * @param size size of format_time buffer
 * @return number of bytes placed in format_time (excluding terminating null byte)
*/
int
iso8601_time_str(char* format_time, size_t size, const time_t *time);

#endif
