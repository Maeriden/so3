#!/bin/sh

confdir="/tmp/os3-1701014"
docsdir="/tmp/os3-1701014/root"

mkdir -p "${confdir}"
mkdir -p "${docsdir}"

cat > "${confdir}/config.ini" << EOF
listen_port_plain     = 8080
listen_port_crypt     = 8081
extra_processes_count = 3
extra_threads_count   = 3
disable_authorization = 0
documents_root        = ${docsdir}
EOF

cat > "${confdir}/users" << EOF
root:root
user:user

test:test
EOF


mkdir -p "${docsdir}/commands"
ln -s "/bin/date" "${docsdir}/commands/"
ln -s "/bin/echo" "${docsdir}/commands/"

cat > "${docsdir}/file" << EOF
This string is inside ${docsdir}/file
EOF


mkdir -p "${docsdir}/dir"
mkdir -p "${docsdir}/dir/subdir"

cat > "${docsdir}/dir/file1" << EOF
This string is inside ${docsdir}/dir/file1
EOF
cat > "${docsdir}/dir/file2" << EOF
This string is inside ${docsdir}/dir/file2
EOF



# if [ ! -f bin/users ]; then
# 	echo "[$(date +%T)] Creating dummy user database"
# 	cat > "bin/users" << EOF
# admin:admin
# user:user

# test:test
# EOF
# fi


# if [ ! -f bin/config ]; then
# 	echo "[$(date +%T)] Creating dummy config file"
# 	cat > bin/config << EOF
# listen_port_plain = 8080
# listen_port_crypt = 8081
# documents_root = .
# EOF
# fi


# if [ ! -d bin/commands/ ]; then
# 	echo "[$(date +%T)] Creating dummy commands directory"
# 	mkdir bin/commands
# 	ln -s /usr/bin/date bin/commands/
# 	ln -s /usr/bin/echo bin/commands/
# fi
