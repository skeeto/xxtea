.POSIX:
CC      = cc
CFLAGS  = -Os -g -Wall -Wextra -D__USE_MINGW_ANSI_STDIO=0
LDFLAGS =
LDLIBS  =

xxtea$(EXE): xxtea.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ xxtea.c $(LDLIBS)

clean:
	rm -f xxtea$(EXE)
