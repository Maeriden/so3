#!/bin/sh

[ -d "bin/" ] || mkdir "bin/"
[ -d "obj/" ] || mkdir "obj/"

cflags="-std=gnu17 -O0"
dflags="-g3 -DENABLE_ASSERT=1 -DENABLE_DEBUG=1"
define="-DPLATFORM_LINUX=1"
# lflags="-Llibs -llfds711"

echo "[$(date +%T)] Building main"
gcc -c "code/linux-main.c" -o"obj/linux-main.o" ${cflags} ${dflags} ${define}
[ $? -eq 0 ] || exit 1

echo "[$(date +%T)] Linking main"
gcc  "obj/linux-main.o" -o"bin/server" ${lflags} -pthread
[ $? -eq 0 ] || exit 1


if [ -f code/client-get-linux.c ]; then
	echo "[$(date +%T)] Building GET client"
	gcc "code/client-get-linux.c" -o"bin/get" ${cflags} ${dflags} ${define} ${lflags}
fi


if [ -f code/client-put-linux.c ]; then
	echo "[$(date +%T)] Building PUT client"
	gcc "code/client-put-linux.c" -o"bin/put" ${cflags} ${dflags} ${define} ${lflags}
fi


if [ ! -f bin/setup.sh ] && [ -f test/setup.sh ]; then
	echo "[$(date +%T)] Creating bin/setup.sh"
	cp test/setup.sh bin/setup.sh
fi
