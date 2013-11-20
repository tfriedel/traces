#ifndef _PORTABLE_SNPRINTF_H_
#define _PORTABLE_SNPRINTF_H_
#if defined(__cplusplus)
extern "C" {
#endif
#define PORTABLE_SNPRINTF_VERSION_MAJOR 2
#define PORTABLE_SNPRINTF_VERSION_MINOR 2

/* Define HAVE_SNPRINTF if your system already has snprintf and vsnprintf.
 *
 * If HAVE_SNPRINTF is defined this module will not produce code for
 * snprintf and vsnprintf, unless PREFER_PORTABLE_SNPRINTF is defined as well,
 * causing this portable version of snprintf to be called portable_snprintf
 * (and portable_vsnprintf).
 */
#define HAVE_SNPRINTF

/* Define PREFER_PORTABLE_SNPRINTF if your system does have snprintf and
 * vsnprintf but you would prefer to use the portable routine(s) instead.
 * In this case the portable routine is declared as portable_snprintf
 * (and portable_vsnprintf) and a macro 'snprintf' (and 'vsnprintf')
 * is defined to expand to 'portable_v?snprintf' - see file snprintf.h .
 * Defining this macro is only useful if HAVE_SNPRINTF is also defined,
 * but does does no harm if defined nevertheless.
 */
#define PREFER_PORTABLE_SNPRINTF

/* Define SNPRINTF_LONGLONG_SUPPORT if you want to support
 * data type (long long int) and length modifier 'll' (e.g. %lld).
 * If undefined, 'll' is recognized but treated as a single 'l'.
 *
 * If the system's sprintf does not handle 'll'
 * the SNPRINTF_LONGLONG_SUPPORT must not be defined!
 *
 * This is off by default as (long long int) is a language extension.
 */
#define SNPRINTF_LONGLONG_SUPPORT

#ifdef HAVE_SNPRINTF
#include <stdio.h>
#else
extern int snprintf(char *, size_t, const char *, /*args*/ ...);
extern int vsnprintf(char *, size_t, const char *, va_list);
#endif

#if defined(HAVE_SNPRINTF) && defined(PREFER_PORTABLE_SNPRINTF)
extern int portable_snprintf(char *str, size_t str_m, const char *fmt, /*args*/ ...);
extern int portable_vsnprintf(char *str, size_t str_m, const char *fmt, va_list ap);
#define snprintf  portable_snprintf
#define vsnprintf portable_vsnprintf
#endif

extern int asprintf  (char **ptr, const char *fmt, /*args*/ ...);
extern int vasprintf (char **ptr, const char *fmt, va_list ap);
extern int asnprintf (char **ptr, size_t str_m, const char *fmt, /*args*/ ...);
extern int vasnprintf(char **ptr, size_t str_m, const char *fmt, va_list ap);

#endif
#if defined(__cplusplus)
}
#endif
