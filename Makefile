# If Windows, then assume the compiler is `gcc` for the
# MinGW environment. I can't figure out how to tell if it's
# actually MingGW. FIXME TODO
ifeq ($(OS),Windows_NT)
	CC = gcc
	SHELL = cmd
endif

# Try to figure out the default compiler. I dont know the best
# way to do this with `gmake`. If you have better ideas, please
# submit a pull request on github.
ifeq ($(CC),)
ifneq (, $(shell which clang))
CC = clang
else ifneq (, $(shell which gcc))
CC = gcc
else
CC = cc
endif
endif

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SYS := $(shell $(CC) -dumpmachine)
INSTALL_DATA := -pDm755

# LINUX
# The automated regression tests run on Linux, so this is the one
# environment where things likely will work -- as well as anything
# works on the bajillion of different Linux environments
ifneq (, $(findstring linux, $(SYS)))
ifneq (, $(findstring musl, $(SYS)))
LIBS =  -lssl -lcrypto -lpcre2-8
else
LIBS = -lm -lrt -ldl -lpthread -lssl -lcrypto -lpcre2-8 -lxml2
endif
INCLUDES = 
FLAGS2 = 
LDFLAG = 
endif

# MinGW on Windows
ifneq (, $(findstring mingw, $(SYS)))
INCLUDES = 
LIBS = -lIPHLPAPI -lWs2_32 -lssl -lcrypto -lpcre2-8 -lxml2
FLAGS2 = 
LDFLAG = 
endif

# OpenBSD
ifneq (, $(findstring openbsd, $(SYS)))
LIBS = -lm -lpthread -lssl -lcrypto -lpcre2-8 -lxml2
INCLUDES = -I. 
FLAGS2 = 
LDFLAG = 
endif

# FreeBSD
ifneq (, $(findstring freebsd, $(SYS)))
LIBS = -lm -lpthread -lssl -lcrypto -lpcre2-8 -lxml2
INCLUDES = -I. 
FLAGS2 =
LDFLAG = 
endif

# NetBSD
ifneq (, $(findstring netbsd, $(SYS)))
LIBS = -lm -lpthread -lssl -lcrypto -lpcre2-8 -lxml2
INCLUDES = -I. 
FLAGS2 =
LDFLAG = 
endif


DEFINES = 

bin/xtate: CFLAGS = $(FLAGS2) $(INCLUDES) $(DEFINES) -Wall -O3 -std=gnu99 -DNDEBUG
bin/xtate_debug: CFLAGS = $(FLAGS2) $(INCLUDES) $(DEFINES) -Wall -O0 -g -ggdb -fno-pie -std=gnu99
bin/xtate_debug: LDFLAGS = $(LDFLAG) -rdynamic -no-pie

.SUFFIXES: .c .cpp

all: bin/xtate


# just compile everything in the 'src' directory. Using this technique
# means that include file dependencies are broken, so sometimes when
# the program crashes unexpectedly, 'make clean' then 'make' fixes the
# problem that a .h file was out of date
tmp/%.o: \
	src/%.c \
	src/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/crypto/%.c \
	src/crypto/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/massip/%.c \
	src/massip/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/pixie/%.c \
	src/pixie/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/proto/%.c \
	src/proto/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/rawsock/%.c \
	src/rawsock/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/scripting/%.c \
	src/scripting/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/stack/%.c \
	src/stack/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/stub/%.c \
	src/stub/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/templ/%.c \
	src/templ/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/util-misc/%.c \
	src/util-misc/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/util-scan/%.c \
	src/util-scan/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/util-data/%.c \
	src/util-data/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/util-out/%.c \
	src/util-out/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/smack/%.c \
	src/smack/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/nmap/%.c \
	src/nmap/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/probe-modules/%.c \
	src/probe-modules/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/probe-modules/lzr-probes/%.c \
	src/probe-modules/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/scan-modules/%.c \
	src/scan-modules/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/output-modules/%.c \
	src/output-modules/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/timeout/%.c \
	src/timeout/*.h
	$(CC) $(CFLAGS) -c $< -o $@

tmp/%.o: \
	src/recog/%.c \
	src/recog/*.h
	$(CC) $(CFLAGS) -c $< -o $@


SRC = $(sort $(wildcard \
	src/*.c \
	src/crypto/*.c \
	src/massip/*.c \
	src/pixie/*.c \
	src/proto/*.c \
	src/rawsock/*.c \
	src/scripting/*.c \
	src/stack/*.c \
	src/stub/*.c \
	src/templ/*.c \
	src/util-misc/*.c \
	src/util-scan/*.c \
	src/util-data/*.c \
	src/util-out/*.c \
	src/smack/*.c \
	src/nmap/*.c \
	src/probe-modules/*.c \
	src/probe-modules/lzr-probes/*.c \
	src/scan-modules/*.c \
	src/output-modules/*.c \
	src/timeout/*.c \
	src/recog/*.c \
	))
OBJ = $(addprefix tmp/, $(notdir $(addsuffix .o, $(basename $(SRC))))) 


bin/xtate: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

bin/xtate_debug: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS) $(LIBS)

ifneq ($(OS),Windows_NT)
debug: bin/xtate_debug
endif

ifeq ($(OS),Windows_NT)
clean:
	del /F tmp\*.o
	del /F bin\xtate.exe
	del /F bin\xtate_debug.exe
else
clean:
	rm -f tmp/*.o
	rm -f bin/xtate
	rm -f bin/xtate_debug
endif

ifneq ($(OS),Windows_NT)
install: bin/xtate
	install $(INSTALL_DATA) bin/xtate $(DESTDIR)$(BINDIR)/xtate
endif

regress: bin/xtate
	bin/xtate --selftest

test: regress

default: bin/xtate