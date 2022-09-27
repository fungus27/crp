vpath %.c src
vpath %.h src
OBJ := main.o cipher.o digest.o util.o aes.o rc4.o md5.o sha1.o sha2.o
CFLAGS := -Wall -I"include"

main: $(OBJ)
main.o cipher.o aes.o rc4.o: include/crp/cipher.h
main.o digest.o md5.o sha1.o sha2.o: include/crp/digest.h
cipher.o aes.o rc4.o: cipher_internal.h
digest.o md5.o sha1.o sha2.o: digest_internal.h
util.o digest.o aes.o md5.o sha1.o sha2.o: util.h

clean:
	rm *.o

.PHONY: clean
