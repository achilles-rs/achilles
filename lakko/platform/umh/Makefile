CC      = gcc
LD	= ld
RANLIB	= ranlib
CFLAGS  = -Wall -O2 -MD -I ../../
LDFLAGS = -O2 -L. -L ../../lakko/platform/pal/ -L ../socket/target/release/ -lsandbox -llakko -lsocket -lpthread -T sandbox.ld
OBJ     = boxer.o umm.o trap.o exec.o

all: libsandbox.a

libsandbox.a: $(OBJ)
	$(AR) cr $(@) $(OBJ)
	$(RANLIB) $(@)

clean:
	rm -f *.o test *.d libsandbox.a

-include *.d
