#ifndef TRACE_UTIL_H
#define TRACE_UTIL_H
// extern __thread 

#include <iostream>
#include <string>
static unsigned short trace_current_nesting;
static int defaultMaxLogCallsPerFunction = 10;

static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}

static inline void trace_decrement_nesting_level(void)
{
    //if (trace_current_nesting > 0) {
        trace_current_nesting--;
    //}
}

static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
#endif
