#!/bin/sh

[ -d "bin/" ] || mkdir "bin/"
[ -d "obj/" ] || mkdir "obj/"

cflags="-std=gnu17 -Iinclude -O0"
dflags="-g3 -DENABLE_ASSERT=1 -DENABLE_DEBUG=1"
define="-DPLATFORM_LINUX=1"
# lflags="-Llibs -llfds711"

echo "[$(date +%T)] Building main"
gcc -c -oobj/main.o ${cflags} ${dflags} ${define} code/main.c
[ $? -eq 0 ] || exit 1

echo "[$(date +%T)] Linking main"
gcc -obin/server obj/main.o ${lflags} -pthread
[ $? -eq 0 ] || exit 1


if [ -f code/client-get-linux.c ]; then
	echo "[$(date +%T)] Building GET client"
	gcc -obin/get ${cflags} ${dflags} ${define} code/client-get-linux.c ${lflags}
fi


if [ -f code/client-put-linux.c ]; then
	echo "[$(date +%T)] Building PUT client"
	gcc -obin/put ${cflags} ${dflags} ${define} code/client-put-linux.c ${lflags}
fi


if [ ! -f bin/setup.sh ] && [ -f test/setup.sh ]; then
	echo "[$(date +%T)] Creating bin/setup.sh"
	cp test/setup.sh bin/setup.sh
fi
