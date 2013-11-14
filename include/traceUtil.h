#ifndef TRACE_UTIL_H
#define TRACE_UTIL_H
// extern __thread 

#define TRACE_CURRENT_FILENAME __TRACE_SOURCE_FILENAME

static int defaultMaxLogCallsPerFunction = 10;

#include "traceUtil.h"


namespace tracer
{
static void trace_increment_nesting_level(void);
static void trace_decrement_nesting_level(void);
static unsigned short trace_get_nesting_level(void);

#ifndef __ADSPBLACKFIN__
__attribute__((no_instrument_function))
#endif
void trace_log_func_entry(char *cpp_filename, char *funcName, char *logText, unsigned int lineNo,
                          bool *entry_was_logged, int *traceCounter, int defaultMaxLogCallsPerFunction, ...);

}


//#include <iosfwd>
//#include <memory>


//// allows printing of variables of any type
//namespace outputter_any_detail
//{
//    // your generic output function
//    template <typename T>
//    std::ostream& output_generic(std::ostream& pStream, const T& pX)
//    {
//        // note: safe from recursion. if you accidentally try
//        // to output pX again, you'll get a compile error
//        //return pStream << "unknown type at address: " << &pX;
//        return pStream << "[unknown type]";
//    }

//    // any type can be converted to this type,
//    // but all other conversions will be
//    // preferred before this one
//    class any
//    {
//    public:
//        // stores a type for later output
//        template <typename T>
//        any(const T& pX) :
//        mPtr(new any_holder<T>(pX))
//        {}

//        // output the stored type generically
//        std::ostream& output(std::ostream& pStream) const
//        {
//            return mPtr->output(pStream);
//        }

//    private:
//        // hold any type
//        class any_holder_base
//        {
//        public:
//            virtual std::ostream& output(std::ostream& pStream) const = 0;
//            virtual ~any_holder_base(void) {}
//        };

//        template <typename T>
//        class any_holder : public any_holder_base
//        {
//        public:
//            any_holder(const T& pX) :
//            mX(pX)
//            {}

//            std::ostream& output(std::ostream& pStream) const
//            {
//                return output_generic(pStream, mX);
//            }

//        private:
//            const T& mX;
//            any_holder& operator=(const any_holder&);
//        };

//        std::auto_ptr<any_holder_base> mPtr;
//        any& operator=(const any&);
//    };

//    // hidden so the generic output function
//    // cannot accidentally call this fall-back
//    // function (leading to infinite recursion)
//    namespace detail
//    {
//        // output a type converted to any. this being a conversion allows
//        // other conversions to partake in overload resolution
//        inline std::ostream& operator<<(std::ostream& pStream, const any& pAny)
//        {
//            return pAny.output(pStream);
//        }
//    }

//    // a transfer class, to allow
//    // a unique insertion operator
//    template <typename T>
//    class outputter_any
//    {
//    public:
//        outputter_any(const T& pX) :
//          mX(pX)
//          {}

//          const T& get(void) const
//          {
//              return mX;
//          }

//    private:
//        const T& mX;
//        outputter_any& operator=(const outputter_any&);
//    };

//    // this is how outputter_any's get outputted,
//    // found outside the detail namespace by ADL
//    template <typename T>
//    std::ostream& operator<<(std::ostream& pStream, const outputter_any<T>& pX)
//    {
//        // bring in the fall-back insertion operator
//        using namespace detail;

//        // either a specifically defined operator,
//        // or the generic one via a conversion to any
//        return pStream << pX.get();
//    }
//}

//// construct an outputter_any
//template <typename T>
//outputter_any_detail::outputter_any<T> output_any(const T& pX)
//{
//    return outputter_any_detail::outputter_any<T>(pX);
//}

#endif // TRACE_UTIL_H
