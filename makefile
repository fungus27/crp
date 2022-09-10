vpath %.c src
vpath %.h src
OBJ := main.o cipher.o digest.o util.o aes.o rc4.o
CFLAGS := -Wall

main: $(OBJ)

main.o cipher.o aes.o rc4.o: cipher.h
main.o util.o digest.o aes.o: util.h
main.o digest.o: digest.h

clean:
	rm *.o

.PHONY: clean
