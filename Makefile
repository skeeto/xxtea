.POSIX:
CC      = cc
CFLAGS  = -Os -g -Wall -Wextra
LDFLAGS =
LDLIBS  =

xxtea: xxtea.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ xxtea.c $(LDLIBS)

clean:
	rm -f xxtea
