CC      = gcc
CFLAGS  = -Wall -g -O3 -MD
LDFLAGS = -static -L. -llakko
OBJ     = entry.o lakko.o vsyscall.o elf.o vm.o util.o page.o procmap.o debug.o
NOFPU_OBJ = trap.o

$(NOFPU_OBJ): EXTRA_FLAGS := -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float

all: liblakko.a

liblakko.a: $(OBJ) $(NOFPU_OBJ)
	$(AR) crD $(@) $(OBJ) $(NOFPU_OBJ)

clean:
	rm -f *.o test *.d liblakko.a

-include *.d

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) -o $@ -c $<
