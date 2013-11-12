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
import subprocess
import errno

plugin_path = os.getenv('TRACE_INSTRUMENTOR',
                        os.path.join(os.path.dirname(sys.argv[0]),
                        'trace_instrumentor/trace_instrumentor.so'))
clang_path = os.getenv('TRACE_CLANG_PATH', 'clang-3.1')

print 'starting ccwrap.py'
print 'plugin_path = %s' % (plugin_path, )
print 'clang_path = %s' % (clang_path, )

traceUtil_h = os.path.join(os.path.dirname(sys.argv[0]), "include/traceUtil.h")
cppPrepend = open(traceUtil_h,"r").readlines()

use_includes = True

def spawn(args):
    print 'spawn: ', " ".join(args)
    return os.spawnvp(os.P_WAIT, args[0], args)


class Error(Exception):

    pass


def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

def translate(
    orig_c_file_basename,
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
    args.extend(['-load', plugin_path, '-plugin', 'trace-instrument', "-plugin-arg-trace-instrument", orig_c_file_basename])
    try:
        print 'running clang :', " ".join(args)
        output = subprocess.check_output(args, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError, e:
        print 'clang returned', e.returncode
        print 'Args:', ' '.join(args)
        print 'Output:', e.output
        return 1

    return 0


def translate_no_gcc(
    orig_c_file_basename,
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
        '-Xclang',
        "-plugin-arg-trace-instrument",
        '-Xclang',
        orig_c_file_basename
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
    orig_c_file_basename,
    pp_file,
    out_pp_file,
    language,
    arch_triplet,
    cflags,
    ):

    try:
        return translate(orig_c_file_basename, pp_file, out_pp_file, language, arch_triplet,
                         cflags)
    except Error, e:
        print e.args[0]
        return -1


def maybe_translate_no_gcc(
    orig_c_file_basename,
    pp_file,
    out_pp_file,
    language,
    arch_triplet,
    cflags,
    ):

    try:
        return translate_no_gcc(orig_c_file_basename, pp_file, out_pp_file, language,
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
    lines = [line.replace("\r","") for line in lines]    
    f.close()
    prepend_lines = cppPrepend
    lines = prepend_lines + lines

    # write output

    with open(outputfilename, 'w') as f:
        f.writelines(lines)

def main():
    args = sys.argv[1:]
    if '-c' not in args:
        return spawn(args)
        #return ldmodwrap_main()

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
        +'.pp'
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
    abs_c_file = os.path.abspath(c_file)    
    last_part = abs_c_file[len(os.path.commonprefix([abs_c_file, outputdir])):]
    #last_part = last_part[last_part.find('/')+1:]
    output_c_file = os.path.join(outputdir, last_part)
    make_sure_path_exists(os.path.dirname(output_c_file))

    # preprocess c++ file, insert trace counter etc

    orig_c_file = c_file
    orig_c_file_basename = os.path.basename(orig_c_file)
    if not use_includes:
        c_file = pp_file + '.pre.cpp'
        preProcess(orig_c_file, c_file)
    print 'cpp_args[c_index]=', cpp_args[c_index]
    cpp_args[c_index] = c_file
    print 'cpp_args[c_index]=', cpp_args[c_index]
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
    # cpp_args.extend(["-include", os.path.join(os.path.dirname(sys.argv[0]),  "include/trace_lib.h")])
    # cpp_args.extend(["-include", os.path.join(os.path.dirname(sys.argv[0]),  "include/trace_user.h")])
    if use_includes:
        cpp_args.extend(["-include", traceUtil_h])
    print 'cpp_args: ', " ".join(cpp_args)
    out_pp_file = pp_file + '.i'
    clang_args = cpp_args[1:]

    # clang_args[clang_args.index('-E')] = '-c'

    clang_args[clang_args.index(pp_file)] = output_c_file
    cpp_args.extend(['-C'])
    clang_ret = maybe_translate_no_gcc(orig_c_file_basename, c_file, out_pp_file + '.out',
            language, get_arch_triplet(args[0]), clang_args)
    preProcess(output_c_file, output_c_file)
    #if clang_ret != 0:
    #    return -1
    ret = spawn(cpp_args)
    if ret:
        return ret
    clang_ret = 0

    try:
        clang_ret = maybe_translate(orig_c_file_basename, pp_file, out_pp_file, language,
                                    get_arch_triplet(args[0]), cflags)
        if clang_ret != 0:
            return -1

        comp_args = []
        comp_args.extend(list(args))
        if '-o' not in comp_args:
            o_file = os.path.splitext(c_file)[0] + '.o'
            comp_args.extend(['-o', o_file])

        comp_args[c_index] = out_pp_file        
        ret = spawn(comp_args)
        return ret
    finally:

        # os.unlink(pp_file)

        if os.getenv('TRACE_NO_UNLINK_PPFILE', '') == '':

            # Delete the pp.i file only if the clang invocation was successful

            if clang_ret == 0:
                os.unlink(out_pp_file)
                if c_file != orig_c_file:
                    os.unlink(c_file)


if __name__ == '__main__':
    sys.exit(main())
