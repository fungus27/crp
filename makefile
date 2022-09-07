OBJ := main.o cipher.o util.o aes.o rc4.o
CFLAGS := -Wall

main: $(OBJ)

main.o: main.c util.h cipher.h
cipher.o: cipher.c cipher.h
util.o: util.c util.h
aes.o: aes.c util.h cipher.h
rc4.o: rc4.c cipher.h

clean:
	rm *.o

.PHONY: clean
