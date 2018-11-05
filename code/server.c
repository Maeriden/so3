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
	size_t    content_len;
	const u8* content;
} HTTPRequest;



static
const_Str0 http_reason(u32 status_code)
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
	} return "";
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
u32 server_format_response(u8* buffer, size_t buffer_size, u32 status, u8* content, u32 content_len)
{
	static const_Str0 FORMAT_OK = "\
HTTP/1.0 %u %s\r\n\
Server: os3-1701014/1.0.0\r\n\
Content-Type: text/plain\r\n\
Content-Length: %u\r\n\
\r\n\
%.*s";
	
	static const_Str0 FORMAT_UNAUTHORIZED = "\
HTTP/1.0 %u %s\r\n\
Server: os3-1701014/1.0.0\r\n\
Content-Type: text/plain\r\n\
Content-Length: %u\r\n\
WWW-Authenticate: Basic\r\n\
\r\n\
%.*s";
	
	const_Str0 format = FORMAT_OK;
	if(status == HTTP_STATUS_UNAUTHORIZED)
		format = FORMAT_UNAUTHORIZED;
	
	return snprintf(buffer, buffer_size, format,
	                status, http_reason(status),
	                content_len,
	                content_len, content);
}


static
i32 server_send_response(socket_t socket, u32 http_status, u8* content, u32 content_size)
{
	u32  buffer_len = server_format_response(NULL, 0, http_status, content, content_size);
	Str0 buffer     = memory_alloc(char, buffer_len+1);
	if(!buffer)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	server_format_response(buffer, buffer_len+1, http_status, content, content_size);
	
	u32 sent_count = 0;
	i32 error = platform_send(socket, buffer, buffer_len, &sent_count);
	ASSERT(sent_count == buffer_len);
	memory_free(char, buffer, buffer_len+1);
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
	
	u32 buffer_count = buffer_size / sizeof(u32);
	memcpy(buffer, response_content, response_content_size);
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
		
		HTTP_STATUS http_status = platform_put_resource(state, request->path, request->path_len, request->content, request->content_len);
		if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
		{
			PRINT_ERROR("put_resource_content() failed");
		}
		
		return http_status;
	}
	
	
	if(strN_beginswith0(request->method, request->method_len, "GET"))
	{
		// Path must never have a trailing slash when it gets to the platform layer
		if(request->path[request->path_len-1] == '/')
		{
			request->path[request->path_len-1] = 0;
			request->path -= 1;
		}
		
		HTTP_STATUS http_status = platform_get_resource(state, request->path, request->path_len, out_response, out_response_size);
		if(HTTP_STATUS_IS_SERVER_ERROR(http_status))
		{
			PRINT_ERROR("get_resource_content() failed");
		}
		*out_syslog_resource_size = *out_response_size;
		
		return http_status;
	}
	
	
	return HTTP_STATUS_NOT_IMPLEMENTED;
}


static
HTTP_STATUS server_recv_request(socket_t socket, u8** out_buffer, u32* out_buffer_size, HTTPRequest* out_request)
{
	*out_buffer      = NULL;
	*out_buffer_size = 0;
	
	u32 buffer_size = 4096;
	u8* buffer      = memory_alloc(u8, buffer_size);
	if(!buffer)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	
	HTTP_STATUS http_status = 200;
	
	b32 recv_remain_found = 0;
	u32 recv_remain       = 0;
	u32 recv_total        = 0;
	until(recv_remain_found && recv_remain == 0)
	{
		u8* avail_buffer      = buffer      + recv_total;
		u32 avail_buffer_size = buffer_size - recv_total;
		
		u32 recv_count = 0;
		if(platform_recv(socket, avail_buffer, avail_buffer_size, &recv_count) != 0)
		{
			PRINT_ERROR("platform_recv() failed");
			memory_free(u8, buffer, buffer_size);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
		
		if(recv_count == 0)
		{
			PRINT_WARN("platform_recv() read 0 bytes");
			break;
		}
		recv_total += recv_count;
		
		if(recv_remain_found)
		{
			recv_remain -= recv_count;
			if(recv_remain == 0)
				break;
		}
		else
		{
			if(strN_indexofN(avail_buffer, recv_count, "\r\n\r\n", 4) != recv_count)
			{
				recv_remain_found = 1;
				recv_remain       = 0;
				
				HTTPRequest request = {0};
				int consumed_size = server_parse_request(buffer, recv_total, &request);
				if(consumed_size < 1)
				{
					// PRINT_DEBUG("server_parse_request() failed");
					memory_free(u8, buffer, buffer_size);
					return HTTP_STATUS_BAD_REQUEST;
				}
				
				struct phr_header* xpct_header = server_find_header(request.headers, request.headers_count, "Expect");
				if(xpct_header)
				{
					http_status = HTTP_STATUS_EXPECTATION_FAILED;
					break;
				}
				
				struct phr_header* clen_header = server_find_header(request.headers, request.headers_count, "Content-Length");
				if(clen_header)
				{
					u8* request_content = buffer + consumed_size;
					
					u32 nontent_len = request_content - buffer;
					u32 content_already_received_len = recv_total - nontent_len;
					
					u32 content_len = strtoul(clen_header->value, NULL, 10);
					u32 content_not_yet_received_len = content_len - content_already_received_len;
					
					recv_remain = content_not_yet_received_len;
					
					// TODO: Perform a final allocation now that the message size is known?
				}
				else
				{
					// NOTE: Seems like not sending a Content-Length in a GET is ok
					//PRINT_DEBUG("server_find_header(%s) failed", "Content-Length");
					//memory_free(u8, buffer, buffer_size);
					//return HTTP_STATUS_BAD_REQUEST;
				}
			}
		}
		
		
		if(recv_total == buffer_size)
		{
			if(recv_remain > 0 || !recv_remain_found)
			{
				u32 new_buffer_size = buffer_size + 4096;
				u8* new_buffer      = memory_realloc(u8, buffer, buffer_size, new_buffer_size);
				if(!new_buffer)
				{
					memory_free(u8, buffer, buffer_size);
					return HTTP_STATUS_INTERNAL_SERVER_ERROR;
				}
				buffer      = new_buffer;
				buffer_size = new_buffer_size;
			}
		}
	}
	
	HTTPRequest request = {0};
	int noncontent_len = server_parse_request(buffer, recv_total, &request);
	if(noncontent_len < 1)
	{
		memory_free(u8, buffer, buffer_size);
		return HTTP_STATUS_BAD_REQUEST;
	}
	
	*out_request = request;
	if(out_request->method) out_request->method[out_request->method_len] = 0;
	if(out_request->path)   out_request->path[out_request->path_len]     = 0;
	
	struct phr_header* clen_header = server_find_header(out_request->headers, out_request->headers_count, "Content-Length");
	out_request->content     = clen_header ? buffer + noncontent_len               : NULL;
	out_request->content_len = clen_header ? strtoul(clen_header->value, NULL, 10) : 0;
	
	*out_buffer      = buffer;
	*out_buffer_size = buffer_size;
	return http_status;
}


void server_serve_client(State* state, socket_t socket, u32 encryption_key, u8 address[4])
{
	u32 request_buffer_size = 0;
	u8* request_buffer      = NULL;
	
	u32 response_buffer_size = 0;
	u8* response_buffer      = NULL;
	
	HTTPRequest request = {0};
	HTTP_STATUS http_status = server_recv_request(socket, &request_buffer, &request_buffer_size, &request);
	
	b32 do_syslog = 1;
	u32 syslog_resource_size = 0;
	if(HTTP_STATUS_IS_SUCCESS(http_status))
	{
		http_status = server_handle_request(state, socket, &request, &response_buffer, &response_buffer_size, &syslog_resource_size);
		if(HTTP_STATUS_IS_SUCCESS(http_status))
		{
			if(server_encrypt_response(response_buffer, response_buffer_size, encryption_key) != 0)
			{
				PRINT_ERROR("server_encrypt_response() failed");
				http_status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			}
		}
	}
	
	
	if(server_send_response(socket, http_status, response_buffer, response_buffer_size) == 0)
	{
		if(do_syslog)
		{
			Str0 userid = server_extract_userid(&request);
			if(platform_syslog(address, userid, request.method, request.path, request.minor_version, http_status, syslog_resource_size) != 0)
			{
				PRINT_ERROR("platform_syslog() failed");
			}
			if(userid)
				memory_free(char, userid, strlen(userid));
		}
	}
	else
	{
		PRINT_ERROR("server_send_response() failed");
	}
	
	memory_free(u8, request_buffer,  request_buffer_size);
	memory_free(u8, response_buffer, response_buffer_size);
}
