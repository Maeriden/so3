#!/bin/bash

confdir="/tmp/os3-1701014/conf"
docsdir="/tmp/os3-1701014/docs"
logsdir="/tmp/os3-1701014/logs"

mkdir -p "${confdir}"
mkdir -p "${docsdir}"
mkdir -p "${logsdir}"



cat > "${confdir}/config.ini" << EOF
listen_port_plain     = 8080
listen_port_crypt     = 8081
extra_processes_count = 0
extra_threads_count   = 0
disable_authorization = 0
documents_root        = ${docsdir}
log_level             = 2
EOF

cat > "${confdir}/users" << EOF
root:root
user:user
EOF



mkdir -p "${docsdir}/commands"
ln -s "/bin/date" "${docsdir}/commands/"
# ln -s "/bin/echo" "${docsdir}/commands/"



cat > "${docsdir}/file.txt" << EOF
Contenuto di file.txt
EOF



dd if=/dev/zero    bs=1K count=1  > "${docsdir}/zero.bin"                    #  1KB file of zeroes
dd if=/dev/zero    bs=1K count=1  | tr "\000" "\377" > "${docsdir}/one.bin"  #  1KB file of ones
dd if=/dev/urandom bs=1M count=64 | tr "\000" "\377" > "${docsdir}/rand.bin" # 16MB file of random data



mkdir -p "${docsdir}/subdir"

cat > "${docsdir}/subdir/1.txt" << EOF
Contenuto di ${docsdir}/subdir/1.txt
EOF
cat > "${docsdir}/subdir/2.txt" << EOF
Contenuto di ${docsdir}/subdir/2.txt
EOF
cat > "${docsdir}/subdir/3.txt" << EOF
Contenuto di ${docsdir}/subdir/3.txt
EOF
