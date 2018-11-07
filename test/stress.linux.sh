#!/bin/bash

function get()
{
	local i="$1"
	local logfile="$2"
	local rempath="$3"
	# local locpath="$4"
	
	curl --http1.0 --basic "root:root@127.0.0.1:8080/${rempath}" > "${logfile}" 2>&1
	if [ $? == 0 ]; then
		echo "Request $i completed"
		rm "${logfile}"
	else
		echo "Request $i __FAILED__"
	fi
}

function put()
{
	local i="$1"
	local logfile="$2"
	local rempath="$3"
	local locpath="$4"
	
	curl --http1.0 --basic --upload "${locpath}" "root:root@127.0.0.1:8080/${rempath}" > "${logfile}" 2>&1
	if [ $? == 0 ]; then
		echo "Request $i completed"
		rm "${logfile}"
	else
		echo "Request $i __FAILED__"
	fi
}

if (( $# < 2 )); then
	echo "Usage: ${0} GET|PUT request_count"
	exit
fi

if [[ "${1}" != "GET" && "${1}" != "PUT" ]]; then
	echo "Usage: ${0} GET|PUT request_count"
	exit
fi

if [[ "${2}" < 1 ]]; then
	echo "Usage: ${0} GET|PUT request_count"
	exit
fi

datedir="$(date)"
datedir="${datedir// /_}"
datedir="${datedir//:/_}"
logpath="$(mktemp --directory --tmpdir "${datedir}.XXX")"
request_count=${2:-0}

case "${1}" in
	
"GET")
	for (( i = 1; i <= ${request_count}; ++i )); do
		get $i "${logpath}/$i.txt" "file.txt" &
		# get $i "${logpath}/$i.txt" "rand.bin" &
	done
	wait
	;;

"PUT")
	for (( i = 1; i <= ${request_count}; ++i )); do
		put $i "${logpath}/$i.txt" "${datedir}/$i.txt" "file.txt" &
		# put $i "${logpath}/$i.txt" "${datedir}/$i.txt" "rand.bin" &
	done
	wait
	;;
esac
