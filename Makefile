CFLAGS=-Iinclude/ -c -Wall -g -fPIC

TRACE_LLVM_CONFIG_PATH?=/home/friedel/opt/clang+llvm-3.1-x86_64-linux-ubuntu-11.10/bin/llvm-config
#TRACE_LLVM_CONFIG_PATH?=/usr/bin/llvm-config-3.4
LLVM_CONFIG=$(TRACE_LLVM_CONFIG_PATH)
H2XML = $(shell which h2xml h2xml.py | head -1)
XML2PY = $(shell which xml2py xml2py.py | head -1)

all: libtrace libtraceuser simple_trace_reader trace_dumper interactive_reader trace_instrumentor

libtrace: libtrace.a traces.so
trace_dumper: trace_dumper/trace_dumper
libtraceuser: libtraceuser.a
simple_trace_reader: trace_reader/simple_trace_reader
interactive_reader: interactive_reader/_trace_parser_ctypes.py

LIBTRACEUSER_FILES:=trace_metadata_util halt trace_user
LIBTRACE_FILES:=trace_metadata_util halt cached_file trace_parser
LIBTRACE_OBJS=$(LIBTRACE_FILES:%=libtrace/%.o)
LIBTRACEUSER_OBJS=$(LIBTRACEUSER_FILES:%=libtrace/%.o)

libtrace.a traces.so: $(LIBTRACE_OBJS) 
	ar rcs libtrace.a $^
	gcc -shared -g -o traces.so $^

trace_dumper/trace_dumper: $(LIBTRACE_OBJS) trace_dumper/trace_dumper.o trace_dumper/filesystem.o trace_dumper/trace_user_stubs.o
	gcc -L.  trace_dumper/filesystem.o trace_dumper/trace_dumper.o trace_dumper/trace_user_stubs.o -ltrace  -o trace_dumper/trace_dumper -lrt

libtraceuser.a: $(LIBTRACEUSER_OBJS)
	ar rcs libtraceuser.a $^

trace_reader/simple_trace_reader: $(LIBTRACE_OBJS) trace_reader/simple_trace_reader.o
	gcc -L. trace_reader/simple_trace_reader.o -ltrace -o trace_reader/simple_trace_reader

interactive_reader/_trace_parser_ctypes.py: include/trace_parser.h
	$(H2XML)  -c -I. include/trace_parser.h -o _trace_parser_ctypes.xml
	$(XML2PY) -k f -k e -k s _trace_parser_ctypes.xml > interactive_reader/_trace_parser_ctypes.py
	rm _trace_parser_ctypes.xml

trace_instrumentor/trace_instrumentor.o: CXXFLAGS := $(shell $(LLVM_CONFIG) --cxxflags) -Iinclude/ -I/home/friedel/opt/clang+llvm-3.1-x86_64-linux-ubuntu-11.10/include -std=c++0x
trace_instrumentor/trace_instrumentor.o: LDFLAGS := $(shell $(LLVM_CONFIG) --libs --ldflags)
trace_instrumentor: trace_instrumentor/trace_instrumentor.o
	gcc $(LDFLAGS) -shared trace_instrumentor/trace_instrumentor.o  -o trace_instrumentor/trace_instrumentor.so

clean:
	find -name \*.o -exec rm \{} \;
	rm *.so *.a
	rm interactive_reader/_trace_parser_ctypes.py

