#!/bin/sh

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


cflags="/nologo /MDd /EHsc"
lflags="/nologo /subsystem:console /incremental:no /opt:ref"

cl.exe "win32-date.c" /Fe:"date.exe" ${cflags} /link ${lflags}
