#include "platform.h"
#include "base64.c"

#define HTTP_STATUS_IS_SUCCESS(status)      ( 200 <= (status) && (status) <= 299 )
#define HTTP_STATUS_IS_CLIENT_ERROR(status) ( 400 <= (status) && (status) <= 499 )
#define HTTP_STATUS_IS_SERVER_ERROR(status) ( 500 <= (status) && (status) <= 599 )


typedef struct phr_header PhrHeader;

typedef struct HTTPRequest
{
	int       minor_version;
	size_t    method_len;
	Str0      method;
	size_t    path_len;
	Str0      path;
	size_t    headers_count;
	PhrHeader headers[16];
	size_t    content_offset;
	size_t    content_len;
	u8*       content;
} HTTPRequest;



static
const_Str0 get_http_reason(u32 status_code)
{
	switch(status_code) {
		case 100: return "Continue";
		case 200: return "OK";
		case 201: return "Created";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 417: return "Expectation Failed";
		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
	} return "UNKNOWN";
}


static
PhrHeader* server_find_header(PhrHeader headers[], u32 headers_count, const_Str0 sought_name)
{
	for(u32 i = 0; i < headers_count; ++i)
		if(strN_indexof0(headers[i].name, headers[i].name_len, sought_name) != headers[i].name_len)
			return headers + i;
	return NULL;
}


static
Str0 server_extract_userid(HTTPRequest* request)
{
	Str0 result = NULL;
	PhrHeader* auth_header = server_find_header(request->headers, request->headers_count, "Authorization");
	if(auth_header)
	{
		u32 OFF = strlen("Basic ");
		size_t auth_string_len = 0;
		u8*    auth_string     = base64_decode(auth_header->value+OFF, auth_header->value_len-OFF, &auth_string_len);
		if(auth_string)
		{
			u32 sep_i = strN_indexofN(auth_string, auth_string_len, ":", 1);
			result = strN_dup0(auth_string, sep_i);
			free(auth_string);
		}
	}
	return result;
}


static
i32 server_send_response(socket_t socket, HTTP_STATUS http_status, u8* content, u32 content_len)
{
	const_Str0 http_reason     = get_http_reason(http_status);
	u32        http_reason_len = strlen(http_reason);
	
	#define STRLEN(s) ( sizeof(s)-1 )
	u32 headers_len = 0;
	{
		headers_len += STRLEN("HTTP/1.0 000 \r\n") + http_reason_len;
		headers_len += STRLEN("Server: os3-1701014/1.0.0\r\n");
		
		if(http_status == HTTP_STATUS_UNAUTHORIZED)
		{
			headers_len += STRLEN("WWW-Authenticate: Basic\r\n");
		}
		
		if(content_len > 0)
		{
			headers_len += STRLEN("Content-Type: text/plain\r\n");
			headers_len += STRLEN("Content-Length: \r\n") + digits_count_u64(content_len);
		}
		headers_len += STRLEN("\r\n");
	}
	#undef STRLEN
	
	u32  buffer_size = headers_len + content_len;
	Str0 buffer      = memory_alloc(char, buffer_size);
	if(!buffer)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	
	#define BUFFER_APPEND(s) memcpy(buffer+offset, s, sizeof(s)-1); offset += sizeof(s)-1
	{
		u32 offset = 0;
		
		BUFFER_APPEND("HTTP/1.0");
		buffer[offset++] = ' ';
		buffer[offset++] = ( (http_status / 100)     ) + '0';
		buffer[offset++] = ( (http_status / 10) % 10 ) + '0';
		buffer[offset++] = ( (http_status % 10)      ) + '0';
		buffer[offset++] = ' ';
		memcpy(buffer+offset, http_reason, http_reason_len);
		offset += http_reason_len;
		BUFFER_APPEND("\r\n");
		
		BUFFER_APPEND("Server: os3-1701014/1.0.0");
		BUFFER_APPEND("\r\n");
		
		if(http_status == HTTP_STATUS_UNAUTHORIZED)
		{
			BUFFER_APPEND("WWW-Authenticate: Basic");
			BUFFER_APPEND("\r\n");
		}
		
		if(content_len > 0)
		{
			BUFFER_APPEND("Content-Type: text/plain");
			BUFFER_APPEND("\r\n");
			
			BUFFER_APPEND("Content-Length: ");
			offset += format_number(buffer+offset, buffer_size-offset, content_len);
			BUFFER_APPEND("\r\n");
		}
		
		BUFFER_APPEND("\r\n");
		memcpy(buffer+offset, content, content_len);
	}
	#undef BUFFER_APPEND
	
	u32 sent_count = 0;
	i32 error = platform_send(socket, buffer, headers_len+content_len, &sent_count);
	memory_free(char, buffer, buffer_size);
	if(error)
	{
		PRINT_ERROR("platform_send() failed");
	}
	return error;
}


static
i32 server_encrypt_response(u8* response_content, u32 response_content_size, u32 encryption_key)
{
	if(response_content == NULL || response_content_size == 0 || encryption_key == 0)
		return 0;
	
	// Round up to multiple of 4
	u32  buffer_size = (response_content_size + 3) & ~3;
	u32* buffer      = memory_alloc(u8, buffer_size);
	if(!buffer)
		return -1;
	
	memcpy(buffer, response_content, response_content_size);
	u32 buffer_count = buffer_size / sizeof(*buffer);
	for(u32 i = 0; i < buffer_count; ++i)
		buffer[i] = buffer[i] ^ encryption_key;
	memcpy(response_content, buffer, response_content_size);
	memory_free(u8, buffer, buffer_size);
	return 0;
}


static
int server_parse_request(u8* buffer, u32 buffer_size, HTTPRequest* out_request)
{
	out_request->headers_count = ARRAY_COUNT(out_request->headers);
	int consumed_size = phr_parse_request(buffer, buffer_size,
	                                      (const char**)&out_request->method, &out_request->method_len,
	                                      (const char**)&out_request->path,   &out_request->path_len,
	                                      &out_request->minor_version,
	                                      out_request->headers, &out_request->headers_count,
	                                      0);
	return consumed_size;
}


static
b32 server_check_authorization(State* state, char* auth_string, u32 auth_string_len)
{
	if(state->config.disable_authorization)
		return 1;
	
	if(auth_string && auth_string_len > 0)
	{
		ASSERT(state->users != NULL || state->users_count == 0);
		
		for(u32 i = 0; i < state->users_count; ++i)
			if(str0_indexofN(state->users[i], auth_string, auth_string_len) == 0)
				return 1;
	}
	return 0;
}


static
HTTP_STATUS server_handle_request(State* state, socket_t socket, HTTPRequest* request, u8** out_response, u32* out_response_size,
	                              u32* out_syslog_resource_size)
{
	*out_response      = NULL;
	*out_response_size = 0;
	
	if(request->path_len < 1)
		return HTTP_STATUS_BAD_REQUEST;
	ASSERT(request->method != NULL);
	ASSERT(request->path != NULL);
	
	struct phr_header* xpct_header = server_find_header(request->headers, request->headers_count, "Expect");
	if(xpct_header)
	{
		return HTTP_STATUS_EXPECTATION_FAILED;
	}
	
	if(!state->config.disable_authorization)
	{
		size_t auth_string_len = 0;
		u8*    auth_string     = NULL;
		struct phr_header* auth_header = server_find_header(request->headers, request->headers_count, "Authorization");
		if(auth_header)
		{
			u32 offset = strlen("Basic ");
			auth_string = base64_decode(auth_header->value+offset, auth_header->value_len-offset, &auth_string_len);
			if(!auth_string)
			{
				PRINT_ERROR("base64_decode() failed");
				return HTTP_STATUS_INTERNAL_SERVER_ERROR;
			}
		}
		else
		{
			return HTTP_STATUS_UNAUTHORIZED;
		}
	
		b32 authorized = server_check_authorization(state, auth_string, auth_string_len);
		free(auth_string);
		if(!authorized)
			return HTTP_STATUS_FORBIDDEN;
	}
	
	
	
	if(strN_beginswith0(request->method, request->method_len, "PUT"))
	{
		*out_syslog_resource_size = request->content_len;
		
		if(request->path[request->path_len-1] == '/')
		{
			// Forbid PUTing using a path that looks like a directory
			return HTTP_STATUS_FORBIDDEN;
		}
		
		if(str0_beginswith0(request->path, "/commands"))
		{
			// Forbid PUTing to commands directory
			return HTTP_STATUS_FORBIDDEN;
		}
		
		Str0 full_path = str0_cat0(state->config.documents_root, request->path);
		if(!full_path)
		{
			*out_syslog_resource_size = 0;
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
		
		HTTP_STATUS http_status = platform_put_resource(state, full_path, request->content, request->content_len);
		str0_free(full_path, strlen(full_path));
		if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
		{
			PRINT_ERROR("platform_put_resource() failed");
		}
		
		return http_status;
	}
	
	
	if(strN_beginswith0(request->method, request->method_len, "GET"))
	{
		Str0 full_path = str0_cat0(state->config.documents_root, request->path);
		if(!full_path)
		{
			*out_syslog_resource_size = 0;
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
		
		HTTP_STATUS http_status = 0;
		if(str0_beginswith0(request->path, "/commands/") && request->path_len > sizeof("/commands/")-1)
		{
			http_status = platform_run_resource(state, full_path, out_response, out_response_size);
			if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
				PRINT_ERROR("platform_run_command() failed");
		}
		else
		{
			http_status = platform_get_resource(state, full_path, out_response, out_response_size);
			if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
				PRINT_ERROR("platform_get_resource() failed");
		}
		
		str0_free(full_path, strlen(full_path));
		*out_syslog_resource_size = *out_response_size;
		return http_status;
	}
	
	
	return HTTP_STATUS_NOT_IMPLEMENTED;
}


static
u32 server_recv_request_content(socket_t socket, u8* buffer, u32 buffer_size, u32 content_len, HTTP_STATUS* out_status)
{
	ASSERT(buffer_size >= content_len);
	
	*out_status = HTTP_STATUS_OK;
	u32 recv_total = 0;
	while(recv_total < content_len)
	{
		u32 avail_buffer_size = buffer_size - recv_total;
		u8* avail_buffer      = buffer      + recv_total;
		
		u32 recv_count = 0;
		i32 error = platform_recv(socket, avail_buffer, avail_buffer_size, &recv_count);
		if(error)
		{
			PRINT_ERROR("platform_recv() failed");
			*out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			break;
		}
		
		// NOTE: In the case of a ECONNRESET, we consider it a bad request since the content data
		// is not the same as the declared Content-Length
		if(recv_count == 0)
		{
			*out_status = HTTP_STATUS_BAD_REQUEST;
			break;
		}
		
		recv_total += recv_count;
	}
	return recv_total;
}


static
u32 server_recv_request(socket_t socket, u8** out_buffer, u32* out_buffer_size, HTTPRequest* out_request, HTTP_STATUS* out_status)
{
	*out_buffer      = NULL;
	*out_buffer_size = 0;
	*out_status      = HTTP_STATUS_OK;
	
	u32 buffer_size = 4096;
	u8* buffer      = memory_alloc(u8, buffer_size);
	if(!buffer)
	{
		*out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		return 0;
	}
	
	u32 recv_total = 0;
	b32 headers_found = 0;
	until(headers_found)
	{
		if(recv_total == buffer_size)
		{
			u32 new_buffer_size = buffer_size + 4096;
			u8* new_buffer      = memory_realloc(u8, buffer, buffer_size, new_buffer_size);
			if(!new_buffer)
			{
				memory_free(u8, buffer, buffer_size);
				*out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
				return recv_total;
			}
			buffer      = new_buffer;
			buffer_size = new_buffer_size;
		}
		
		u8* avail_buffer      = buffer      + recv_total;
		u32 avail_buffer_size = buffer_size - recv_total;
		
		u32 recv_count = 0;
		i32 error = platform_recv(socket, avail_buffer, avail_buffer_size, &recv_count);
		if(error)
		{
			PRINT_ERROR("platform_recv() failed");
			memory_free(u8, buffer, buffer_size);
			*out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			return recv_total;
		}
		
		// NOTE: If client closes connection early, recv will signal ECONNRESET and recv_count will be 0
		if(recv_count == 0)
		{
			memory_free(u8, buffer, buffer_size);
			*out_status = HTTP_STATUS_BAD_REQUEST;
			return recv_total;
		}
		
		recv_total += recv_count;
		headers_found = strN_containsN(avail_buffer, recv_count, "\r\n\r\n", 4);
	}
	
	
	HTTPRequest request = {0};
	int consumed_size = server_parse_request(buffer, recv_total, &request);
	if(consumed_size < 1)
	{
		PRINT_ERROR("server_parse_request() failed");
		memory_free(u8, buffer, buffer_size);
		*out_status = HTTP_STATUS_BAD_REQUEST;
		return recv_total;
	}
	request.content_offset = consumed_size;
	request.content = buffer + request.content_offset;
	
	ASSERT(request.method);
	ASSERT(request.path);
	ASSERT(request.method_len > 0);
	ASSERT(request.path_len > 0);
	
	struct phr_header* clen_header = server_find_header(request.headers, request.headers_count, "Content-Length");
	if(clen_header)
	{
		request.content_len = strtoul(clen_header->value, NULL, 10);
	}
	
	// Resize buffer to the exact size we need for the request
	u32 final_buffer_size = request.content_offset + request.content_len;
	if(final_buffer_size != buffer_size)
	{
		u8* final_buffer = memory_realloc(u8, buffer, buffer_size, final_buffer_size);
		if(final_buffer)
		{
			buffer      = final_buffer;
			buffer_size = final_buffer_size;
			if(server_parse_request(buffer, recv_total, &request) == consumed_size)
			{
				request.content = buffer + request.content_offset;
			}
			else
			{
				PRINT_ERROR("server_parse_request() failed");
				*out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			}
		}
		else
		{
			*out_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
	}
	
	request.method[request.method_len] = 0;
	request.path[request.path_len]     = 0;
	
	*out_buffer      = buffer;
	*out_buffer_size = buffer_size;
	*out_request     = request;
	return recv_total;
}


void server_serve_client(State* state, socket_t socket, u32 encryption_key, ipv4_addr_t address)
{
	u32 request_buffer_size = 0;
	u8* request_buffer      = NULL;
	
	u32 response_buffer_size = 0;
	u8* response_buffer      = NULL;
	
	u32 syslog_resource_size = 0;
	HTTPRequest request     = {0};
	HTTP_STATUS http_status = HTTP_STATUS_OK;
	
	u32 recv_count = server_recv_request(socket, &request_buffer, &request_buffer_size, &request, &http_status);
	if(HTTP_STATUS_IS_SUCCESS(http_status))
	{
		ASSERT(recv_count > 0);
		
		u32 content_buffer_len = request_buffer_size - recv_count;
		u8* content_buffer     = request_buffer      + recv_count;
		u32 remaining_content_len = request.content_offset + request.content_len - recv_count;
		
		recv_count += server_recv_request_content(socket, content_buffer, content_buffer_len, remaining_content_len, &http_status);
		if(HTTP_STATUS_IS_SUCCESS(http_status))
		{
			ASSERT(recv_count == request.content_offset + request.content_len);
			
			http_status = server_handle_request(state, socket, &request, &response_buffer, &response_buffer_size, &syslog_resource_size);
			if(HTTP_STATUS_IS_SUCCESS(http_status) && encryption_key != 0)
			{
				if(server_encrypt_response(response_buffer, response_buffer_size, encryption_key) != 0)
				{
					PRINT_ERROR("server_encrypt_response() failed");
					http_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
				}
			}
			else if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
			{
				PRINT_ERROR("server_handle_request() failed");
			}
		}
		else if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
		{
			PRINT_ERROR("server_recv_request_content() failed");
		}
	}
	else if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
	{
		PRINT_ERROR("server_recv_request() failed");
	}
	
	
	if(server_send_response(socket, http_status, response_buffer, response_buffer_size) == 0)
	{
		Str0 userid = server_extract_userid(&request);
		if(platform_syslog(address, userid, request.method, request.path, request.minor_version, http_status, syslog_resource_size) != 0)
		{
			PRINT_ERROR("platform_syslog() failed");
		}
		if(userid)
			memory_free(char, userid, strlen(userid));
	}
	else
	{
		PRINT_ERROR("server_send_response() failed");
	}
	
	memory_free(u8, request_buffer,  request_buffer_size);
	memory_free(u8, response_buffer, response_buffer_size);
}
