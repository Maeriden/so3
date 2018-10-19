#ifndef PLATFORM_H
#define PLATFORM_H 1

#include <stdint.h>
typedef  int8_t  i8;
typedef  int16_t i16;
typedef  int32_t i32;
typedef  int64_t i64;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef u32  b32;

// NOTE: These types simply mean the string is expected to be null-terminated
typedef char*       Str0;
typedef const char* const_Str0;

i32 platform_recv(int socket, u8** out_data, u32* out_data_size);
i32 platform_send(int socket, u8* data, u32 data_size);
i32 platform_check_authorization(Str0 auth_string, u32 auth_string_len, b32* out_authorized);
i32 platform_put_resource(Str0 resource_path, u32 resource_path_len, const u8* content, u32 content_size);
i32 platform_get_resource(Str0 resource_path, u32 resource_path_len, u8** out_content, u32* out_content_size);
i32 platform_syslog(u8 address[4], const_Str0 userid, const_Str0 method, const_Str0 path, u32 minor, u32 status, u32 resource_size);

#endif
