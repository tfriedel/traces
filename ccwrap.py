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

TRACES_PROGRAM_START_MARKER = '//TRACES_PROGRAM_START_MARKER\n'
def postProcess(filename, outputfilename):
    f = open(filename, 'r')
    lines = f.readlines()
    f.close()

    lineNo = 0
    markedLineNo = -1
    for line in lines:
        if line.startswith(TRACES_PROGRAM_START_MARKER[:-1]):
            markedLineNo = lineNo
            break
        lineNo += 1
    if markedLineNo >= 0:
        lines = lines[markedLineNo:]    
    # write output
    with open(outputfilename, 'w') as f:
        f.writelines(lines)
    
def preProcess(filename, outputfilename):
    f = open(filename, 'r')
    lines = f.readlines()
    f.close()

    lastIncludeLineNo = 0
    for line in lines:
        if line.startswith('#include'):
            lastIncludeLineNo += 1

    lines.insert(lastIncludeLineNo, TRACES_PROGRAM_START_MARKER)

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
        pp_file = o_file + '.pp'
        cpp_args.append('-o')
        cpp_args.append(pp_file)
    else:
        o_index = args.index('-o') + 1
        o_file = cpp_args[o_index]
        pp_file = o_file + '.pp'
        cpp_args[o_index] = pp_file

    #preprocess c++ file, insert marker after include statements
    orig_c_file = c_file
    c_file = pp_file + ".pre.cpp"
    preProcess(orig_c_file, c_file)
    cpp_args[c_index] = c_file

    handle_dependency_option(cpp_args, c_index, o_index, o_file)
    source_data = file(c_file).read()
    if 'ANDROID_SINGLETON_STATIC_INSTANCE' in source_data:
        return spawn(args)

    # Hack for dealing with sources that use _GNU_SOURCE

    if '#define _GNU_SOURCE' in source_data:
        cpp_args.extend(['-w', '-D', '_GNU_SOURCE'])
    cpp_args.extend(['-C'])
    cflags = get_cflags(args)
    if p.endswith('cpp'):
        language = 'c++'
    else:
        language = 'c'

    cpp_args.extend(['-D', '__TRACE_INSTRUMENTATION'])
    cpp_args.extend(['-include',
                    os.path.join(os.path.dirname(sys.argv[0]),
                    'include/trace_lib.h')])
    cpp_args.extend(['-include',
                    os.path.join(os.path.dirname(sys.argv[0]),
                    'include/trace_user.h')])

    out_pp_file = pp_file + '.i'
    print cpp_args
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
        postProcess(out_pp_file, c_file)
        return ret        
    finally:

        # os.unlink(pp_file)

        if os.getenv('TRACE_NO_UNLINK_PPFILE', '') == '':

            # Delete the pp.i file only if the clang invocation was successful

            if clang_ret == 0:
                pass


                # os.unlink(out_pp_file)
                os.unlink

if __name__ == '__main__':
    sys.exit(main())
