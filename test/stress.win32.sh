function get()
{
	out="${2}/${1}.txt"
	curl --http1.0 --basic "root:root@127.0.0.1:8080/file" > "${out}" 2>&1
	if [ $? == 0 ]; then
		echo "Request ${1} completed"
		rm "${out}"
	else
		echo "Request ${1} __FAILED__"
	fi
}

function put()
{
	out="${2}/${1}.txt"
	curl --http1.0 --basic --upload "${3}" "root:root@127.0.0.1:8080/${2}/putfile-${1}.txt" > "${out}" 2>&1
	if [ $? == 0 ]; then
		echo "Request ${1} completed"
		rm "${out}"
	else
		echo "Request ${1} __FAILED__"
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

request_count=${2:-0}
dir="$(date)"
dir="${dir// /_}"
dir="${dir//:/_}"
mkdir "${dir}"

case "${1}" in
	
"GET")
	for (( i = 1; i <= ${request_count}; ++i )); do
		get "$i" "${dir}" &
	done
	wait
	;;

"PUT")
	for (( i = 1; i <= ${request_count}; ++i )); do
		put "$i" "${dir}" "putfile.txt" &
	done
	wait
	;;
esac
