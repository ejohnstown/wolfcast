LDFLAGS=-lwolfssl

all: wolfcast

key-socket.o: key-socket.c key-socket.h

key-services.o: key-services.c key-services.h key-socket.h

wolfcast.o: wolfcast.c wolfcast.h

wolfcast: wolfcast.o key-socket.o key-services.o

clean:
	rm -rf *.o wolfcast

.PHONY: clean all
