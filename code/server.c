#include "platform.h"
#include "base64.c"


enum HTTP_STATUS
{
	HTTP_STATUS_OK                    = 200,
	HTTP_STATUS_CREATED               = 201,
	HTTP_STATUS_BAD_REQUEST           = 400,
	HTTP_STATUS_UNAUTHORIZED          = 401,
	HTTP_STATUS_NOT_FOUND             = 404,
	HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
	HTTP_STATUS_NOT_IMPLEMENTED       = 501,
};


typedef struct HTTPRequest
{
	int               minor_version;
	size_t            method_len;
	Str0              method;
	size_t            path_len;
	Str0              path;
	size_t            headers_count;
	struct phr_header headers[16];
	size_t            content_len;
	const u8*         content;
} HTTPRequest;



static
const char* http_reason(u32 status_code)
{
	switch(status_code) {
		case 200: return "OK";
		case 201: return "Created";
		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 404: return "Not Found";
		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
	} return "";
}


static
u32 format_response(u8* buffer, size_t buffer_size, u32 status, u8* content, u32 content_size)
{
	static char* format = "\
HTTP/1.0 %u %s\r\n\
Server: os3-1701014/1.0.0\r\n\
Content-Type: text/plain\r\n\
Content-Length: %u\r\n\
\r\n\
%.*s";
	return snprintf(buffer, buffer_size, format,
	                status, http_reason(status),
	                content_size,
	                content_size, content);
}


static
i32 send_response(int socket, u32 http_status, u8* content, u32 content_size)
{
	u32  outgoing_data_len = format_response(NULL, 0, http_status, content, content_size);
	Str0 outgoing_data     = memory_alloc(char, outgoing_data_len+1);
	if(!outgoing_data)
	{
		return -1;
	}
	format_response(outgoing_data, outgoing_data_len+1, http_status, content, content_size);
	
	i32 error = platform_send(socket, outgoing_data, outgoing_data_len);
	memory_free(char, outgoing_data, outgoing_data_len+1);
	if(error)
	{
		PRINT_ERROR("platform_send() failed");
	}
	return error;
}


i32 _parse_request(u8* incoming_data, u32 incoming_data_size, HTTPRequest* request)
{
	request->headers_count = ARRAY_COUNT(request->headers);
	
	int consumed_size = phr_parse_request(incoming_data, incoming_data_size,
	                                      (const char**)&request->method, &request->method_len,
	                                      (const char**)&request->path,   &request->path_len,
	                                      &request->minor_version,
	                                      request->headers, &request->headers_count,
	                                      0);
	if(consumed_size < 0)
	{
		// NOTE: Assume client made a valid request and we suck
		PRINT_ERROR("phr_parse_request() failed");
		return -1;
	}
	request->content_len = incoming_data_size - consumed_size;
	request->content     = incoming_data      + consumed_size;
	
	// Null-terminate by replacing space with \0
	request->method[request->method_len] = 0;
	request->path[request->path_len]     = 0;
	
	return 0;
}


i32 process_client_request(int socket, u8* incoming_data, u32 incoming_data_size,
                           u8** out_response_content, u32* out_response_content_size,
                           Str0* out_userid, Str0* out_method, Str0* out_path,  
                           u32* out_minor_version, u32* out_resource_size)
{
	HTTPRequest request = {};
	if(_parse_request(incoming_data, incoming_data_size, &request) != 0)
	{
		PRINT_ERROR("phr_parse_request() failed");
		return 500;
	}
	
	*out_method = strN_dup0(request.method, request.method_len);
	*out_path   = strN_dup0(request.path, request.path_len);
	*out_minor_version = request.minor_version;
	*out_resource_size = request.content_len;
	
	size_t auth_string_len = 0;
	u8*    auth_string     = NULL;
	for(int i = 0; i < request.headers_count; ++i)
	{
		struct phr_header* header = request.headers + i;
		if(strncmp(header->name, "Authorization", header->name_len) == 0)
		{
			auth_string = base64_decode(header->value, header->value_len, &auth_string_len);
			if(!auth_string)
			{
				PRINT_ERROR("base64_decode() failed");
				return 500;
			}
			
			u32 sep_i = 0;
			while(sep_i < auth_string_len && auth_string[sep_i] != ':')
				sep_i += 1;
			*out_userid = strN_dup0(auth_string, sep_i);
			break;
		}
	}
	
	b32 authorized = 0;
	i32 error = platform_check_authorization(auth_string, auth_string_len, &authorized);
	free(auth_string);
	if(error)
	{
		PRINT_ERROR("platform_check_authorization() failed");
		return 500;
	}
	
	if(!authorized)
		return 401;
	
	if(request.path_len == 0)
		return 400;
	
	// Str0 request_path0 = strn_dup0(request.path, request.path_len);
	Str0 request_path0 = request.path;
	if(!request_path0)
		return 500;
	
	i32 http_status = 501;
	if(strN_beginswith0(request.method, request.method_len, "PUT"))
	{
		http_status = 201;
		i32 error = platform_put_resource(request_path0, request.path_len,
		                                  request.content, request.content_len);
		if(error == RESULT_CLIENT_ERROR)
		{
			PRINT_ERROR("put_resource_content() failed");
			http_status = 400;
		} else
		if(error == RESULT_SERVER_ERROR)
		{
			PRINT_ERROR("put_resource_content() failed");
			http_status = 500;
		}
		
	} else
	if(strN_beginswith0(request.method, request.method_len, "GET"))
	{
		http_status = 200;
		int error = platform_get_resource(request_path0, request.path_len,
		                                  out_response_content, out_response_content_size);
		*out_resource_size = *out_response_content_size;
		if(error)
		{
			PRINT_ERROR("get_resource_content() failed");
			http_status = 500;
		}
		ASSERT(out_response_content != NULL);
	}
	
	// free(request_path0);
	return http_status;
}


i32 encode_response_content(u8* response_content, u32 response_content_size, u32 encryption_key)
{
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


i32 client_procedure(int socket, u32 encryption_key, u8 address[4])
{	
	u32   response_status = 0;
	u32   response_content_size = 0;
	u8*   response_content      = NULL;
	
	u32 incoming_data_size = 0;
	u8* incoming_data      = NULL;
	i32 error = platform_recv(socket, &incoming_data, &incoming_data_size);
	if(error == RESULT_SUCCESS)
	{
		ASSERT(incoming_data != NULL);
		
		Str0 userid = NULL;
		Str0 method = NULL;
		Str0 path   = NULL;
		u32  minor_version = 0;
		u32  resource_size = 0;
		response_status = process_client_request(socket, incoming_data, incoming_data_size,
		                                         &response_content, &response_content_size,
		                                         &userid, &method, &path, 
		                                         &minor_version, &resource_size);
		
		platform_syslog(address, userid, method, path, minor_version, response_status, resource_size);
		memory_free(u8, incoming_data, incoming_data_size);
		memory_free(char, userid, strlen(userid));
		memory_free(char, method, strlen(method));
		memory_free(char, path,   strlen(path));
	}
	else if(error == RESULT_CLIENT_ERROR)
	{
		response_status = 400;
	}
	else
	{
		PRINT_ERROR("platform_recv() failed");
		response_status = 500;
	}
	
	if(response_content && encryption_key != 0)
	{
		if(encode_response_content(response_content, response_content_size, encryption_key) != 0)
		{
			memory_free(u8, response_content, response_content_size);
			response_content      = NULL;
			response_content_size = 0;
			response_status = 500;
		}
	}
	
	send_response(socket, response_status, response_content, response_content_size);
	memory_free(u8, response_content, response_content_size);
	
	return 0;
}
