all: wolfcast

wolfcast: wolfcast.c
	gcc -Wall wolfcast.c -o ./wolfcast -lwolfssl

clean:
	rm -rf wolfcast

.PHONY: clean all
