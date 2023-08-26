CC = gcc
CFLAGS = -Wall -Wextra -g         # Add -g for debug symbols
LIBS = -lpcap

all: run

run: main.o lib.o
	$(CC) $(CFLAGS) main.o lib.o -o run $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

lib.o: lib.c
	$(CC) $(CFLAGS) -c lib.c -o lib.o

debug:                              # New target for building with debug symbols
	$(CC) $(CFLAGS) -O0 -g main.c lib.c -o debug_run $(LIBS)

clean:
	rm -f run debug_run *.o
