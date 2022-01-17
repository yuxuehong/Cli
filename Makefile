CC=gcc
CFLAGS=-Wall -g 
LIBS=-lreadline -lncurses -lpthread
STRIP=strip
TARGETDIR=/home/ramfs/sbin

all:prepare vtysh
prepare:
	@echo Parse the cmd directory ...

OBJECT=${patsubst %.c, %.o, ${wildcard *.c cmd/*.c}}
vtysh:${OBJECT}
	${CC} ${CFLAGS} -o $@ $^ ${LIBS}
	#cp vtysh /root/initrd/ramfs/sbin -f
install:vtysh
	${STRIP} vtysh
	#rm -f ${TARGETDIR}/vtysh
	#cp vtysh ${TARGETDIR}/
.c.o:
.c.h:
clean:
	rm -f *.o cmd/*.o vtysh
