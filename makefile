vpath %.c src
vpath %.h src
vpath %.h include/crp
OBJ := sym.o digest.o util.o aes.o rc4.o md5.o sha1.o sha2.o
CFLAGS := -Wall -I"include" -L"lib"
EXAMPLES := $(addprefix examples/bin/,main)

all: lib/libcrp.a examples

lib/libcrp.a: $(OBJ) lib/
	ar rcs $@ $(OBJ)
lib/:
	mkdir lib

sym.o aes.o rc4.o: sym.h
digest.o md5.o sha1.o sha2.o: digest.h
sym.o aes.o rc4.o: sym_internal.h
digest.o md5.o sha1.o sha2.o: digest_internal.h
util.o digest.o aes.o md5.o sha1.o sha2.o: util.h

examples: $(EXAMPLES)

$(EXAMPLES): lib/libcrp.a sym.h digest.h
	$(CC) $(CFLAGS) examples/$(@F).c lib/libcrp.a -o $@
clean:
	rm *.o

.PHONY: clean
