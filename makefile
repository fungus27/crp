OBJ := main.o cipher.o aes.o util.o
CFLAGS := -Wall

main: $(OBJ)

main.o: main.c util.h cipher.h
cipher.o: cipher.c cipher.h
util.o: util.c util.h
aes.o: aes.c util.h cipher.h

clean:
	rm *.o

.PHONY: clean
