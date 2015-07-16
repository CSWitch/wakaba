CC = gcc
CFLAGS = --std=c11 -Wall -Wextra -pipe -march=native -mtune=native
LDFLAGS = -o sfhd

dev: CC = clang
dev: CFLAGS += -g -O0
dev: sfhd

release: CFLAGS += -O2
release: LDFLAGS += -s
release: sfhd

sfhd: main.o socket.o *.h
	$(CC) *.o $(CFLAGS) $(LDFLAGS)

main.o: main.c *.h
	$(CC) main.c $(CFLAGS) -c

server.o: socket.c *.c
	$(CC) socket.c $(CFLAGS) -c

clean:
	rm *.o
	rm sfhd

analyze:
	scan-build clang *.c $(CFLAGS) $(LDFLAGS)
