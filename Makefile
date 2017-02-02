all: wolfcast

wolfcast: wolfcast.c wolfcast.h
	gcc -Wall wolfcast.c -o ./wolfcast -lwolfssl

clean:
	rm -rf wolfcast

.PHONY: clean all
