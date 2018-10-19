#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
// #include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                              "abcdefghijklmnopqrstuvwxyz"
                                              "0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}


int
main(int argc, char** argv)
{
	if(argc < 4)
	{
		fprintf(stderr, "Usage: %s local_path user:pass server_path\n", argv[0]);
		return 1;
	}
	
	int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
	struct sockaddr_in server_socket_address;
	server_socket_address.sin_family      = AF_INET;
	server_socket_address.sin_port        = htons(8080);
	server_socket_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	connect(server_socket, (struct sockaddr*)&server_socket_address, sizeof(server_socket_address));
	
	
	char* local_path = argv[1];
	int local_fd = open(local_path, O_RDONLY);
	if(local_fd == -1)
	{
		fprintf(stderr, "File \"%s\" not found\n", local_path);
		return 1;
	}
	struct stat sb = {};
	fstat(local_fd, &sb);
	size_t local_data_size = sb.st_size;
	// char*  local_data      = mmap(NULL, local_data_size, PROT_READ, MAP_PRIVATE, local_fd, 0);
	char* local_data = calloc(local_data_size, 1);
	read(local_fd, local_data, local_data_size);
	close(local_fd);
	
	
	char* auth = argv[2];
	size_t         auth64_len = 0;
	unsigned char* auth64     = base64_encode(auth, strlen(auth), &auth64_len);
	
	
	char* remote_path = argv[3];
	static char* request_format = "\
PUT %s HTTP/1.0\r\n\
Authorization: %s\r\n\
\r\n\
%.*s";
	int   buffer_size = 1+snprintf(NULL, 0, request_format, remote_path, auth64, local_data_size, local_data);
	char* buffer      = calloc(buffer_size, 1);
	snprintf(buffer, buffer_size, request_format, remote_path, auth64, local_data_size, local_data);
	// munmap(local_data, local_data_size);
	free(local_data);
	
	
	write(server_socket, buffer, strlen(buffer));
	free(buffer);
	shutdown(server_socket, SHUT_WR);
	
	
	buffer_size = 0x10000;
	buffer = calloc(buffer_size, 1);
	ssize_t bytes_received_total = 0;
	while(1)
	{
		void*  available_buffer      = buffer      + bytes_received_total;
		size_t available_buffer_size = buffer_size - bytes_received_total;
		
		ssize_t bytes_received_count = read(server_socket, available_buffer, available_buffer_size);
		if(bytes_received_count == -1)
		{
			if(errno == EINTR)
				continue;
			break;
		}
		
		if(bytes_received_count == 0)
			break; // End-of-File (socket shutdown)
		
		bytes_received_total += bytes_received_count;
		if(bytes_received_total == buffer_size)
		{
			int   new_buffer_size = buffer_size + 0x10000;
			void* new_buffer      = calloc(new_buffer_size, 1);
			
			memmove(new_buffer, buffer, buffer_size);
			free(buffer);
			buffer      = new_buffer;
			buffer_size = new_buffer_size;
		}
	}
	shutdown(server_socket, SHUT_RD);
	close(server_socket);
	
	write(1, buffer, bytes_received_total);
	write(1, "\n", 1);
	free(buffer);
	return 0;
}
