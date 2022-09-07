vpath %.c src
vpath %.h src
OBJ := main.o cipher.o util.o aes.o rc4.o
CFLAGS := -Wall

main: $(OBJ)

main.o cipher.o aes.o rc4.o: cipher.h
main.o util.o aes.o: util.h

clean:
	rm *.o

.PHONY: clean
