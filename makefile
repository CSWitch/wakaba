CC = gcc
CFLAGS = --std=c11 -Wall -Wextra -pipe -march=native -mtune=native -pthread
LDFLAGS = -o sfhd

dev: CC = clang
dev: CFLAGS += -g -O0
dev: sfhd

release: CFLAGS += -O2
release: LDFLAGS += -s
release: sfhd

sfhd: main.o socket.o http.o database.o cache.o request.o *.h
	$(CC) *.o $(CFLAGS) $(LDFLAGS)

main.o: main.c *.h
	$(CC) main.c $(CFLAGS) -c

server.o: socket.c *.h
	$(CC) socket.c $(CFLAGS) -c

http.o: http.c *.h
	$(CC) http.c $(CFLAGS) -c

database.o: database.c *.h
	$(CC) database.c $(CFLAGS) -c

cache.o: cache.c *.h
	$(CC) cache.c $(CFLAGS) -c

request.o: request.c *.h
	$(CC) request.c $(CFLAGS) -c

clean:
	rm *.o
	rm sfhd

analyze:
	scan-build clang *.c $(CFLAGS) $(LDFLAGS)
