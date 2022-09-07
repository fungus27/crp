OBJ := main.o cipher.o
CFLAGS := -Wall

main: $(OBJ)

$(OBJ): cipher.h

clean:
	rm *.o

.PHONY: clean
