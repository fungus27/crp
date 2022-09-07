OBJ := main.o cipher.o aes.o util.o
CFLAGS := -Wall

main: $(OBJ)

$(OBJ): cipher.h util.h

clean:
	rm *.o

.PHONY: clean
