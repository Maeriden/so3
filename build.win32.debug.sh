#!/bin/sh

# set -x

if [ ${HANDBUILD:-0} = 0 ]; then
	
	# Set to own version of MSVC
	msvc_ver='14.14.26428'
	# Set to own version of CSDK
	csdk_ver='10.0.16299.0'
	
	# Enable build script to directly call cl.exe; edit path as necessary
	export PATH="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Tools/MSVC/${msvc_ver}/bin/Hostx64/x64:${PATH}"

	# Set up cl.exe default search paths
	csdk_inc="C:\\Program Files (x86)\\Windows Kits\\10\\Include\\${csdk_ver}"
	csdk_lib="C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\${csdk_ver}"
	msvc_inc="C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Tools\\MSVC\\${msvc_ver}\\include"
	msvc_lib="C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Tools\\MSVC\\${msvc_ver}\\lib\\x64"

	export INCLUDE="${csdk_inc}\\shared;${csdk_inc}\\ucrt;${csdk_inc}\\um;${msvc_inc}"
	export LIB="${csdk_lib}\\ucrt\\x64;${csdk_lib}\\um\\x64;${msvc_lib}"
fi

[ -d "bin/" ] || mkdir "bin/"
[ -d "obj" ]  || mkdir "obj"

optimization_level="d"

cflags="/nologo /MDd /EHsc /Iinclude /O${optimization_level}"
dflags="/Zi /DENABLE_ASSERT=1 /DENABLE_DEBUG=1"
define="/DPLATFORM_WIN32=1"
lflags="/nologo /subsystem:console /incremental:no /opt:ref"


echo "[$(date +%T)] Compiling main"
cl.exe /c "code\\win32-main.c" /Fo"obj\\" /Fd"bin\\win32-main.pdb" ${cflags} ${dflags} ${define}
[ $? -eq 0 ] || exit 1

echo "[$(date +%T)] Linking main"
link.exe "obj\\win32-main.obj" /out:"bin\\server.exe" /debug /pdb:"bin\\win32-main.pdb" ${lflags}
[ $? -eq 0 ] || exit 1
