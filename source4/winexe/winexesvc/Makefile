CFLAGS=-mno-cygwin -Os
LDFLAGS=-mno-cygwin -s -Os

CC_WIN32 := $(shell bash -c 'which {i386,i586}-{mingw32,mingw32msvc}-gcc')
CC_WIN64 := $(shell bash -c 'which {x86_64,amd64}-{mingw32,mingw32msvc}-gcc')

all: winexesvc32_exe.c winexesvc64_exe.c

winexesvc32.exe: winexesvc32.o service32.o
	$(CC_WIN32) $(LDFLAGS) -o $@ $^

winexesvc64.exe: winexesvc64.o service64.o
	$(CC_WIN64) $(LDFLAGS) -o $@ $^

%32.o: %.c
	$(CC_WIN32) -c $(CPPFLAGS) $(CFLAGS) -o $@ $^

%64.o: %.c
	$(CC_WIN64) -c $(CPPFLAGS) $(CFLAGS) -o $@ $^

winexesvc32_exe.c: winexesvc32.exe bin2c.exe
	./bin2c.exe winexesvc32_exe winexesvc32.exe > $@

winexesvc64_exe.c: winexesvc64.exe bin2c.exe
	./bin2c.exe winexesvc64_exe winexesvc64.exe > $@

bin2c.exe: bin2c.c
	gcc -s -o $@ $^

clean:
	-@rm *.exe *.o *_exe.c
