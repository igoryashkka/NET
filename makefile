CC = gcc
CFLAGS = -Wall -Wextra -O1 -g
LIBS = -lpcap

all: run

run: main.o lib.o
	$(CC) $(CFLAGS) main.o lib.o -o run $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

lib.o: lib.c
	$(CC) $(CFLAGS) -c lib.c -o lib.o

clean:
	rm -f run *.o

