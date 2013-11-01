#ifndef TRACE_UTIL_H
#define TRACE_UTIL_H
// extern __thread 

#include <iostream>
#include <string>
#include <pthread.h>
//static unsigned short trace_current_nesting;
extern __thread  unsigned short trace_current_nesting;
static int defaultMaxLogCallsPerFunction = 10;

static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}

static inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}

static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
#endif
