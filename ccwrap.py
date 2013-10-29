#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
#    Sponsored by infinidat (http://infinidat.com)

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import sys
import os
import re
import subprocess

from ldwrap import main as ldmodwrap_main
plugin_path = os.getenv('TRACE_INSTRUMENTOR',
                        os.path.join(os.path.dirname(sys.argv[0]),
                        'trace_instrumentor/trace_instrumentor.so'))
clang_path = os.getenv('TRACE_CLANG_PATH', 'clang')

print 'starting ccwrap.py'
print 'plugin_path = %s' % (plugin_path, )
print 'clang_path = %s' % (clang_path, )

cppPrepend ="""
// extern __thread        
unsigned short ttrace_current_nesting;

static inline void ttrace_increment_nesting_level(void)
{
    trace_current_nesting++;
}

static inline void ttrace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}

static inline unsigned short ttrace_get_nesting_level(void)
{
    return trace_current_nesting;
}
"""

cppPrepend = """
/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#ifndef __TRACE_LIB_H__
#define __TRACE_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define SHM_PATH "/dev/shm/"
#define TRACE_SHM_ID "_trace_shm_"    

#ifndef TRACE_RECORD_BUFFER_RECS
#ifdef ANDROID
#define TRACE_RECORD_BUFFER_RECS  0x10000
#else
#define TRACE_RECORD_BUFFER_RECS  0x100000
#endif /* ANDROID */
#endif /* TRACE_RECORD_BUFFER_RECS */

#endif // _CONFIG_H_

/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#ifndef __TRACE_DEFS_H__
#define __TRACE_DEFS_H__


#ifdef __cplusplus
 extern "C" {
#endif

#define MAX_METADATA_SIZE (0x1000000)
#define TRACE_BUFFER_NUM_RECORDS (3)

     
#define TRACE_SEVERITY_DEF       \
     TRACE_SEV_X(0, INVALID)     \
     TRACE_SEV_X(1, FUNC_TRACE)  \
     TRACE_SEV_X(2, DEBUG)       \
     TRACE_SEV_X(3, INFO)        \
     TRACE_SEV_X(4, WARN)        \
     TRACE_SEV_X(5, ERROR)       \
     TRACE_SEV_X(6, FATAL)       \

enum trace_severity {
#define TRACE_SEV_X(num, name) \
    TRACE_SEV_##name  = num,

TRACE_SEVERITY_DEF
        TRACE_SEV__MIN = 1,
        TRACE_SEV__MAX = 6
#undef TRACE_SEV_X
};

static inline int trace_strcmp(const char *s1, const char *s2)
{
    /* Move s1 and s2 to the first differing characters 
       in each string, or the ends of the strings if they
       are identical.  */
    while (*s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
    }
    /* Compare the characters as unsigned char and
       return the difference.  */
    const unsigned char uc1 = (*(const unsigned char *) s1);
    const unsigned char uc2 = (*(const unsigned char *) s2);
    return ((uc1 < uc2) ? -1 : (uc1 > uc2));
}
     
#define TRACE_SEV_X(num, name)                  \
    if (trace_strcmp(function_name, #name) == 0) { \
        return TRACE_SEV_##name;                \
    }
    
static inline enum trace_severity trace_function_name_to_severity(const char *function_name) {
    TRACE_SEVERITY_DEF;
    #undef TRACE_SEV_X
    return TRACE_SEV_INVALID;
}

enum trace_rec_type {
    TRACE_REC_TYPE_UNKNOWN = 0,
    TRACE_REC_TYPE_TYPED = 1,
    TRACE_REC_TYPE_FILE_HEADER = 2,
    TRACE_REC_TYPE_METADATA_HEADER = 3,
    TRACE_REC_TYPE_METADATA_PAYLOAD = 4,
    TRACE_REC_TYPE_DUMP_HEADER = 5,
    TRACE_REC_TYPE_BUFFER_CHUNK = 6,
    TRACE_REC_TYPE_END_OF_FILE = 7
};

enum trace_log_descriptor_kind {
    TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY = 0,
    TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE = 1,
    TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT = 2,
};

#define TRACE_RECORD_SIZE           64
#define TRACE_RECORD_PAYLOAD_SIZE   44
#define TRACE_RECORD_HEADER_SIZE    (TRACE_RECORD_SIZE - TRACE_RECORD_PAYLOAD_SIZE)

     
enum trace_termination_type {
    TRACE_TERMINATION_LAST = 1,
    TRACE_TERMINATION_FIRST = 2
};

#define TRACE_MACHINE_ID_SIZE    0x18

static inline int trace_compare_generation(unsigned int a, unsigned int b)
{
    if (a >= 0xc0000000   &&  b < 0x40000000)
        return 1;
    if (b > a)
        return 1;
    if (b < a)
        return -1;
    return 0;
}

enum trace_file_type {
    TRACE_FILE_TYPE_JOURNAL = 1,
    TRACE_FILE_TYPE_SNAPSHOT = 2
};

 struct trace_enum_value;
     
 enum trace_type_id {
    TRACE_TYPE_ID_ENUM = 1,
    TRACE_TYPE_ID_RECORD = 2,
    TRACE_TYPE_ID_TYPEDEF = 3
};


struct trace_type_definition {
    enum trace_type_id type_id;
    unsigned int member_count;
    const char *type_name;
    union  {
        // void * is used to allow static initlization of the union in C++, which does not support designated initializors
        void *params;
        struct trace_enum_value *enum_values;
    };
};

 struct trace_enum_value {
    const char *name;
    unsigned int value;
};

struct trace_record {
    /* 20 bytes header */
    unsigned long long ts;
    unsigned short int pid;
    unsigned short int tid;
    short nesting;
    unsigned termination:2;
    unsigned reserved:6;
    unsigned severity:4;
    unsigned rec_type:4;
    unsigned int generation;
    
    /* 44 bytes payload */
    union trace_record_u {
        unsigned char payload[TRACE_RECORD_PAYLOAD_SIZE];
        struct trace_record_typed {
            unsigned int log_id;
            unsigned char payload[0];
        } typed;
        struct trace_record_file_header {
            unsigned char machine_id[TRACE_MACHINE_ID_SIZE];
            unsigned long long boot_time;
        } file_header;
        struct trace_record_metadata {
            unsigned int metadata_size_bytes;
        } metadata;
        struct trace_record_dump_header {
            unsigned int prev_dump_offset;
            unsigned int total_dump_size;
            unsigned int first_chunk_offset;
        } dump_header;
        struct trace_record_buffer_dump {
            unsigned int last_metadata_offset;
            unsigned int prev_chunk_offset;
            unsigned int dump_header_offset;
            unsigned long long ts;
            unsigned int records;
            unsigned int severity_type;
        } buffer_chunk;
    } __attribute__((packed)) u;
} __attribute__((packed));
     
enum trace_param_desc_flags {
    TRACE_PARAM_FLAG_NUM_8    = 0x001,
    TRACE_PARAM_FLAG_NUM_16   = 0x002,
    TRACE_PARAM_FLAG_NUM_32   = 0x004,
    TRACE_PARAM_FLAG_NUM_64   = 0x008,
    TRACE_PARAM_FLAG_VARRAY   = 0x010,
    TRACE_PARAM_FLAG_CSTR     = 0x020,
    
    TRACE_PARAM_FLAG_STR      = 0x040,
    TRACE_PARAM_FLAG_BLOB     = 0x080,
    
    TRACE_PARAM_FLAG_UNSIGNED = 0x100,
    TRACE_PARAM_FLAG_HEX      = 0x200,
    TRACE_PARAM_FLAG_ZERO     = 0x400,
    TRACE_PARAM_FLAG_ENUM     = 0x800,
    TRACE_PARAM_FLAG_NESTED_LOG   = 0x1000,
    TRACE_PARAM_FLAG_ENTER    = 0x2000,
    TRACE_PARAM_FLAG_LEAVE    = 0x4000,
    TRACE_PARAM_FLAG_TYPEDEF  = 0x8000,
    TRACE_PARAM_FLAG_NAMED_PARAM  = 0x10000,
    TRACE_PARAM_FLAG_RECORD  = 0x20000,
    TRACE_PARAM_FLAG_FP  = 0x40000,
};

struct trace_param_descriptor {
    unsigned long flags;
    unsigned long type_id;
    const char *param_name;
    union {
        const char *str;
        const char *const_str;
        const char *type_name;
    };
};

struct trace_log_descriptor {
    enum trace_log_descriptor_kind kind;
    enum trace_severity severity;
    struct trace_param_descriptor *params;
};

struct trace_metadata_region {
    char name[0x100];
    void *base_address;
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    char data[0];
};
     
#ifdef __cplusplus
}
#endif

#endif 

#include <sys/syscall.h>
#include <time.h>    
#include <pthread.h>
#ifdef __repr__
#undef __repr__
#endif
    
#define __repr__ _trace_represent(unsigned int *buf_left, struct trace_record *_record, struct trace_record **__record_ptr, unsigned char **typed_buf)
#ifdef ANDROID
#ifndef _UNISTD_H
    extern int syscall(int __sysno, ...);
#endif //_UNISTD
#else //ANDROID
#ifndef _SYS_SYSCALL_H_
#ifdef __cplusplus     
    extern long int syscall (long int __sysno, ...) throw ();
#else 
    extern long int syscall(long int __sysno, ...);
#endif //__cplusplus
#endif //_SYS_SYSCALL_H_
#endif //ANDROID

#define _O_RDONLY   00000000   
extern struct trace_buffer *current_trace_buffer;
extern struct trace_log_descriptor __static_log_information_start;
extern struct trace_log_descriptor __static_log_information_end;
extern struct trace_type_definition *__type_information_start;

#ifndef ANDROID    
extern __thread unsigned short trace_current_nesting;
#else
extern pthread_key_t nesting_key;
extern pthread_key_t pid_cache_key;
extern pthread_key_t tid_cache_key;
#endif    
#ifdef ANDROID    
static inline unsigned short int trace_get_pid(void)
{
    int *pid = (int *) pthread_getspecific(pid_cache_key);
    if (pid == NULL) {
        pid = (int *) malloc(sizeof(int));
        *pid = syscall(__NR_getpid);
        pthread_setspecific(pid_cache_key, pid);
    }

    return *pid;
}
#else    
static inline unsigned short int trace_get_pid(void)
{
    static __thread int pid_cache = 0;
    if (pid_cache)
        return pid_cache;
    
    pid_cache = syscall(__NR_getpid);
    return pid_cache;
}
#endif    

#ifdef ANDROID    
static inline unsigned short int trace_get_tid(void)
{
    int *tid = (int *) pthread_getspecific(tid_cache_key);
    if (tid == NULL) {
        tid = (int *) malloc(sizeof(int));
        *tid = syscall(__NR_gettid);
        pthread_setspecific(tid_cache_key, tid);
    }

    return *tid;
}
#else    
static inline unsigned short int trace_get_tid(void)
{
    static __thread int tid_cache = 0;
    if (tid_cache)
        return tid_cache;
    
    tid_cache = syscall(__NR_gettid);
    return tid_cache;
}
#endif    
    
static inline unsigned long long trace_get_nsec(void)
{
     struct timespec tv;
     clock_gettime(CLOCK_REALTIME, &tv);
     return ((unsigned long long) tv.tv_sec * 1000000000) + tv.tv_nsec;
}

#ifndef ANDROID    
static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}
#else
static inline void trace_increment_nesting_level(void)
{
    unsigned short *nesting = (unsigned short *) pthread_getspecific(nesting_key);
    if (nesting == NULL) {
        nesting = (unsigned short *) malloc(sizeof(unsigned short));
        *nesting = 1;
        pthread_setspecific(nesting_key, nesting);
    } else {
        (*nesting)++;
    }
}
#endif    

#ifndef ANDROID    
static inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}
#else
static inline void trace_decrement_nesting_level(void)
{
    unsigned short *nesting;
    nesting = (unsigned short *) pthread_getspecific(nesting_key);
    (*nesting)--;
}
#endif    

#ifndef ANDROID    
static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}
#else
static inline unsigned short trace_get_nesting_level(void)
{
    unsigned short *nesting = (unsigned short *) pthread_getspecific(nesting_key);
    if (nesting == NULL) {
        nesting = (unsigned short *) malloc(sizeof(unsigned short));
        *nesting = 0;
        pthread_setspecific(nesting_key, nesting);
        return 5;
    }
    
    return *nesting;
}
#endif    
    
    
#define trace_atomic_t int

static inline int trace_strnlen(const char *c, int l)
{
    int r = 0;

    while (*c  &&  l >= 0) {
        r++;
        c++;
        l--;
    }

    return r;
}

struct trace_records_mutable_metadata {
    trace_atomic_t current_record;
    trace_atomic_t reserved[14];

    unsigned long long latest_flushed_ts;
};

struct trace_records_immutable_metadata {
    unsigned int max_records;
    unsigned int max_records_mask;
    unsigned int max_records_shift;
    unsigned int severity_type;
};

struct trace_records {
    struct trace_records_immutable_metadata imutab;
    struct trace_records_mutable_metadata mutab;
    struct trace_record records[TRACE_RECORD_BUFFER_RECS];
};


struct trace_buffer {
    unsigned int pid;
    union {
        struct trace_records _all_records[TRACE_BUFFER_NUM_RECORDS];
        struct {
            struct trace_records _funcs;
            struct trace_records _debug;
            struct trace_records _other;
        } records;
    } u;
};

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

static inline struct trace_record *trace_get_record(enum trace_severity severity, unsigned int *generation)
{
    struct trace_records *records;
    struct trace_record *record;
    unsigned int record_index;

    if (severity == TRACE_SEV_FUNC_TRACE) {
        records = &current_trace_buffer->u.records._funcs;
    } else if (severity == TRACE_SEV_DEBUG) {
        records = &current_trace_buffer->u.records._debug;
    } else {
        records = &current_trace_buffer->u.records._other;
    }

    record_index = __sync_fetch_and_add(&records->mutab.current_record, 1);
    *generation = record_index >> records->imutab.max_records_shift;
    record_index &= records->imutab.max_records_mask;

    record = &records->records[record_index % TRACE_RECORD_BUFFER_RECS];
    return record;
}
#ifdef __cplusplus
}
#endif
#endif
"""

def spawn(args):
    print 'spawn(%s)' % (args, )
    return os.spawnvp(os.P_WAIT, args[0], args)


class Error(Exception):

    pass


def translate(
    pp_file,
    out_pp_file,
    language,
    arch_triplet,
    cflags,
    ):

    if language == 'c++':
        args = [
            clang_path,
            '-cc1',
            '-w',
            '-Wno-attributes',
            '-fcolor-diagnostics',
            '-fsyntax-only',
            '-fgnu-keywords',
            '-x',
            'c++',
            '-fcxx-exceptions',
            pp_file,
            '-o',
            out_pp_file,
            ]
    else:
        args = [
            clang_path,
            '-cc1',
            '-w',
            '-Wno-attributes',
            '-fcolor-diagnostics',
            '-fsyntax-only',
            '-fgnu-keywords',
            '-std=gnu99',
            pp_file,
            '-o',
            out_pp_file,
            ]

    args.extend(arch_triplet)
    args.extend(cflags)
    args.extend(['-load', plugin_path, '-plugin', 'trace-instrument'])
    try:
        print 'running clang :', args
        output = subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
        print 'clang returned', e.returncode
        print 'Args:', ' '.join(args)
        print 'Output:', e.output
        return 1

    return 0


def translate_no_gcc(
    pp_file,
    out_pp_file,
    language,
    arch_triplet,
    cflags,
    ):

    if language == 'c++':
        args = [
            clang_path,
            '-w',
            '-Wno-attributes',
            '-fcolor-diagnostics',
            '-fsyntax-only',
            '-fgnu-keywords',
            '-x',
            'c++',
            '-fcxx-exceptions',
            ]
    else:
        args = [
            clang_path,
            '-w',
            '-Wno-attributes',
            '-fcolor-diagnostics',
            '-fsyntax-only',
            '-fgnu-keywords',
            '-std=gnu99',
            ]

    args.extend(arch_triplet)
    args.extend(cflags)
    args.extend([
        '-Xclang',
        '-load',
        '-Xclang',
        plugin_path,
        '-Xclang',
        '-plugin',
        '-Xclang',
        'trace-instrument',
        ])
    try:
        print 'running clang :', ' '.join(args)
        output = subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
        print 'clang returned', e.returncode
        print 'Args:', ' '.join(args)
        print 'Output:', e.output
        return 1

    return 0


class UnsupportedTarget(Exception):

    pass


def get_arch_triplet(compiler):
    output = subprocess.check_output([compiler, '-v'],
            stderr=subprocess.STDOUT).split('\n')
    for line in output:
        if line.startswith('Target:'):
            target = line.split(':')[1].strip()
            if target.startswith('arm'):
                return ['-triple', 'armv7-unknown-linux-gnueabi']
            elif target.startswith(('x86', 'i686')):
                return []
            else:
                raise UnsupportedTarget(target)

    raise UnsupportedTarget()


def maybe_translate(
    pp_file,
    out_pp_file,
    language,
    arch_triplet,
    cflags,
    ):

    try:
        return translate(pp_file, out_pp_file, language, arch_triplet,
                         cflags)
    except Error, e:
        print e.args[0]
        return -1


def maybe_translate_no_gcc(
    pp_file,
    out_pp_file,
    language,
    arch_triplet,
    cflags,
    ):

    try:
        return translate_no_gcc(pp_file, out_pp_file, language,
                                arch_triplet, cflags)
    except Error, e:
        print e.args[0]
        return -1


def get_cflags(args):
    cflags = []
    for (i, arg) in enumerate(args):
        if arg.startswith('-I'):
            if arg == '-I':
                cflags.append(arg)
                cflags.append(args[i + 1])
            else:
                cflags.append(arg)

    return cflags


def handle_dependency_option(
    args,
    c_index,
    o_index,
    o_file,
    ):

    new_args = args[::]
    uses_dependency_option = False
    arg_mapping = {'-MMD': '-MM', '-MD': '-M'}
    for (index, arg) in enumerate(new_args):
        if arg in arg_mapping.keys():
            del args[index]
            uses_dependency_option = True
            new_args[index] = arg_mapping[arg]
            break

    if o_index:
        new_args[o_index] = os.path.splitext(o_file)[0] + '.d'

    if uses_dependency_option:
        spawn(new_args)


def preProcess(filename, outputfilename):
    f = open(filename, 'r')
    lines = f.readlines()
    f.close()
    prepend_lines = (cppPrepend.splitlines(True))
    lines = prepend_lines + lines
    # write output
    with open(outputfilename, 'w') as f:
        f.writelines(lines)


def main():
    args = sys.argv[1:]
    if '-c' not in args:
        return ldmodwrap_main()

    c_index = -1
    for (i, p) in enumerate(args):
        if p.endswith('.c') or p.endswith('cpp'):
            c_index = i
            break

    if c_index == -1:
        ret = spawn(args)
        return ret

    c_file = args[c_index]
    cpp_args = list(args)
    cpp_args[args.index('-c')] = '-E'
    o_index = None
    if '-o' not in args:
        o_file = c_file + '.o'
        pp_file = o_file 
        + '.pp'
        cpp_args.append('-o')
        cpp_args.append(pp_file)
    else:
        o_index = args.index('-o') + 1
        o_file = cpp_args[o_index]
        pp_file = o_file + '.pp'
        cpp_args[o_index] = pp_file

    outputdir = os.path.join(os.path.split(os.path.abspath(o_file))[0],
                             'transformed')
    if not os.path.exists(outputdir):
        os.mkdir(outputdir)
    output_c_file = os.path.join(outputdir, os.path.basename(c_file))

    # preprocess c++ file, insert trace counter etc
    orig_c_file = c_file    
    c_file = pp_file + '.pre.cpp'
    preProcess(orig_c_file, c_file)
    print "cpp_args[c_index]=",cpp_args[c_index]
    cpp_args[c_index] = c_file
    print "cpp_args[c_index]=",cpp_args[c_index]
    handle_dependency_option(cpp_args, c_index, o_index, o_file)
    source_data = file(c_file).read()
    if 'ANDROID_SINGLETON_STATIC_INSTANCE' in source_data:
        return spawn(args)

    # Hack for dealing with sources that use _GNU_SOURCE

    if '#define _GNU_SOURCE' in source_data:
        cpp_args.extend(['-w', '-D', '_GNU_SOURCE'])
    cflags = get_cflags(args)
    if p.endswith('cpp'):
        language = 'c++'
    else:
        language = 'c'

    cpp_args.extend(['-D', '__TRACE_INSTRUMENTATION'])    
    # cpp_args.extend(['-include',
    #                 os.path.join(os.path.dirname(sys.argv[0]),
    #                 'include/trace_lib.h')])
    # cpp_args.extend(['-include',
    #                 os.path.join(os.path.dirname(sys.argv[0]),
    #                 'include/trace_user.h')])
    print "cpp_args: ", cpp_args
    out_pp_file = pp_file + '.i'
    print cpp_args
    clang_args = cpp_args[1:]

    # clang_args[clang_args.index('-E')] = '-c'

    clang_args[clang_args.index(pp_file)] = output_c_file
    cpp_args.extend(['-C'])
    clang_ret = maybe_translate_no_gcc(c_file, out_pp_file + '.out',
            language, get_arch_triplet(args[0]), clang_args)
    return 0
    #if clang_ret != 0:
    #    return -1
    ret = spawn(cpp_args)
    if ret:
        return ret
    clang_ret = 0

    try:
        clang_ret = maybe_translate(pp_file, out_pp_file, language,
                                    get_arch_triplet(args[0]), cflags)
        if clang_ret != 0:
            return -1

        comp_args = []
        comp_args.extend(list(args))
        if '-o' not in comp_args:
            o_file = os.path.splitext(c_file)[0] + '.o'
            comp_args.extend(['-o', o_file])

        comp_args[c_index] = out_pp_file
        print comp_args
        ret = spawn(comp_args)
        return ret
    finally:
        # os.unlink(pp_file)
        if os.getenv('TRACE_NO_UNLINK_PPFILE', '') == '':
            # Delete the pp.i file only if the clang invocation was successful
            if clang_ret == 0:
                os.unlink(out_pp_file)
                if c_file != orig_c_file:
                    pass
                    #os.unlink(c_file)


if __name__ == '__main__':
    sys.exit(main())
