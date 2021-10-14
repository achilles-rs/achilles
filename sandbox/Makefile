CC      = gcc
LD	= ld
RANLIB	= ranlib
CFLAGS  = -Wall -O2 -MD -I ../
LDFLAGS = -no-pie -O2 -L ../lakko/platform/umh/ -L ../lakko/platform/pal/ -L ../lakko/socket/target/release/  -lsandbox -llakko -lsocket -lpthread -T ../lakko/platform/umh/sandbox.ld
OBJ     = main.o umm.o trap.o exec.o

all: sandbox

sandbox: sandbox.o ../lakko/platform/umh/libsandbox.a ../lakko/platform/pal/liblakko.a ../lakko/socket/target/release/libsocket.a
	$(CC) -o $(@) $(<) $(LDFLAGS)

clean:
	rm -f *.o *.d sandbox

-include *.d
