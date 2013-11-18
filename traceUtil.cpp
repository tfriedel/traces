#include "traceUtil.h"

#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <iomanip>
#include <string>

namespace tracer {
static const bool indent_using_nesting = false;
static const bool print_trace_counter = false;
}
#ifndef __ADSPBLACKFIN__
#include "boost/thread/tss.hpp"
namespace tracer
{

boost::thread_specific_ptr<unsigned int> trace_current_nesting_ptr;
void trace_increment_nesting_level(void)
{
    if (!trace_current_nesting_ptr.get()) {
        trace_current_nesting_ptr.reset(new unsigned int(0));
    }
    *trace_current_nesting_ptr += 1;
}

void trace_decrement_nesting_level(void)
{
    assert(trace_current_nesting_ptr.get() != NULL);
    *trace_current_nesting_ptr -= 1;
}

unsigned short trace_get_nesting_level(void)
{
    if (!trace_current_nesting_ptr.get()) {
        trace_current_nesting_ptr.reset(new unsigned int(0));
    }
    return *trace_current_nesting_ptr;
}
#else
#include "VdkTLS.h"
namespace tracer
{
#define TLS VdkTLS
TLS<unsigned int> trace_current_nesting;
inline void trace_increment_nesting_level(void)
{
    trace_current_nesting += 1;
}

inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting -= 1;
}

inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
#endif

// __attribute__((no_instrument_function))
// static std::string float_to_hex( float f );

static std::string float_to_hex(float f)
{
    char buff[100];
    sprintf(buff, "%a", f);
    std::string buffAsStdStr = buff;
    return buffAsStdStr;
}

// __attribute__((no_instrument_function))
// static std::string float_to_hex( double d );
static std::string float_to_hex(double d)
{
    char buff[100];
    sprintf(buff, "%a", d);
    std::string buffAsStdStr = buff;
    return buffAsStdStr;
}

// __attribute__((no_instrument_function))
// static std::string float_to_hex( int d );
static std::string float_to_hex(int d)
{
    return float_to_hex(static_cast<float>(d));
}

static std::string getCurrentThreadName()
{
    // boost::this_thread::get_id()
    return NULL;
}
const static int bufferSize = 1000;
void trace_log_func_entry(const char *cpp_filename, const char *funcName, const char *logText,
                          bool *entry_was_logged, int *traceCounter, int defaultMaxLogCallsPerFunction, ...)
{
    if ((*traceCounter)++ < defaultMaxLogCallsPerFunction) {
        char *buffer = new char[bufferSize];
        int cx;
        va_list args;
        va_start(args, defaultMaxLogCallsPerFunction);
        cx = vsprintf(buffer, logText, args);
        va_end(args);
        std::string indent_spaces = "";
        if (indent_using_nesting) {
            indent_spaces = std::string(4 * trace_get_nesting_level() % 40, ' ');
        }
        std::string traceCounterStr = "";
        if (print_trace_counter) {
            std::stringstream ss;
            ss << "#" << *traceCounter << " ";
            traceCounterStr = ss.str();
        }
        std::cout << std::setw(25) << cpp_filename << ": "
                  << indent_spaces << "--> "
                  << traceCounterStr
                  << funcName << "("
                  << buffer << ")" << std::endl;

        *entry_was_logged = true;
        delete[] buffer;
    }
    trace_increment_nesting_level();
}

void trace_log_func_exit(const char *cpp_filename, const char *funcName, const char *logText,
                         bool *entry_was_logged, int defaultMaxLogCallsPerFunction, ...)
{
    trace_decrement_nesting_level();
    if (*entry_was_logged) {
        char *buffer = new char[bufferSize];
        int cx;
        va_list args;
        va_start(args, defaultMaxLogCallsPerFunction);
        cx = vsprintf(buffer, logText, args);
        va_end(args);
        std::string indent_spaces = "";
        if (indent_using_nesting) {
            indent_spaces = std::string(4 * trace_get_nesting_level() % 40, ' ');
        }
        std::cout << std::setw(25) << cpp_filename << ": "
                  << indent_spaces << "<-- " << funcName << "("
                  << buffer << ")" << std::endl;
        delete[] buffer;
    }
}
}
