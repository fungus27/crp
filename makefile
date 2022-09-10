vpath %.c src
vpath %.h src
OBJ := main.o cipher.o digest.o util.o aes.o rc4.o md5.o sha1.o
CFLAGS := -Wall

main: $(OBJ)

main.o cipher.o aes.o rc4.o: cipher.h
main.o util.o digest.o aes.o md5.o sha1.o: util.h
main.o digest.o md5.o sha1.o: digest.h

clean:
	rm *.o

.PHONY: clean
