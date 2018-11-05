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
typedef u32      b32;

// NOTE: These types simply mean the string is expected to be null-terminated
typedef char*       Str0;
typedef const char* const_Str0;




#define until(expr) while(!(expr))
#define ARRAY_COUNT(a) ( sizeof(a) / sizeof(*a) )
#define MIN(a, b)      ( (a) < (b) ? (a) : (b) )
#define LOG_LEVEL_MAX 3




#if PLATFORM_LINUX
	typedef int             filedes_t;
	typedef pid_t           process_t;
	typedef pthread_t       thread_t;
	typedef int             socket_t;
	typedef pthread_mutex_t mutex_t;
	typedef pthread_mutex_t critsec_t;
	typedef pthread_cond_t  condvar_t;
	
	typedef pthread_mutexattr_t mutex_attr_t;
	typedef pthread_mutexattr_t critsec_attr_t;
	typedef pthread_condattr_t  condvar_attr_t;
	
	#define THREAD_CALLBACK_SIGNATURE(name, param_name) void* name(void* param_name)
	#define THREAD_CALLBACK_RETURN                      return NULL
	typedef void* thread_callback_t(void*);
	
	#define SOCKET_SHUTDOWN_R  SHUT_RD
	#define SOCKET_SHUTDOWN_W  SHUT_WR
	#define SOCKET_SHUTDOWN_RW SHUT_RDWR
	
	#define PRINT_ERROR_FL(F, L, ...) platform_print(F, L, 1, "\e[31m[EE] ", __VA_ARGS__)
	#define PRINT_WARN_FL(F, L, ...)  platform_print(F, L, 2, "\e[33m[WW] ", __VA_ARGS__)
	#define PRINT_DEBUG_FL(F, L, ...) platform_print(F, L, 3, "\e[32m[DD] ", __VA_ARGS__)
#endif




#if PLATFORM_WIN32
	typedef HANDLE             filedes_t;
	typedef HANDLE             process_t;
	typedef HANDLE             thread_t;
	typedef SOCKET             socket_t;
	typedef HANDLE             mutex_t;
	typedef CRITICAL_SECTION   critsec_t;
	typedef CONDITION_VARIABLE condvar_t;
	
	typedef SECURITY_ATTRIBUTES mutex_attr_t;
	typedef DWORD               critsec_attr_t;
	typedef void                condvar_attr_t;
	
	#define THREAD_CALLBACK_SIGNATURE(name, param_name) DWORD WINAPI name(LPVOID param_name)
	#define THREAD_CALLBACK_RETURN                      return 0
	typedef DWORD WINAPI thread_callback_t(LPVOID);
	
	#define SOCKET_SHUTDOWN_R  SD_RECEIVE
	#define SOCKET_SHUTDOWN_W  SD_SEND
	#define SOCKET_SHUTDOWN_RW SD_BOTH
	
	#define PRINT_ERROR_FL(F, L, ...) platform_print(F, L, 1, "[EE] ", __VA_ARGS__)
	#define PRINT_WARN_FL(F, L, ...)  platform_print(F, L, 2, "[WW] ", __VA_ARGS__)
	#define PRINT_DEBUG_FL(F, L, ...) platform_print(F, L, 3, "[DD] ", __VA_ARGS__)
#endif




void* platform_memory_alloc (size_t size);
i32   platform_memory_free  (void* addr, size_t size);


void platform_print  (const_Str0 file, int line, u32 level, const_Str0 prefix, const_Str0 format, ...);
i32  platform_syslog (u8 address[4], const_Str0 userid, const_Str0 method, const_Str0 path, u32 minor, u32 status, u32 resource_size);


i32 platform_thread_init (thread_t* thread, thread_callback_t* callback, void* callback_arg);
i32 platform_thread_join (thread_t* thread);


i32 platform_recv (socket_t socket, u8* buffer, u32 buffer_size, u32* out_recv_count);
i32 platform_send (socket_t socket, u8* buffer, u32 buffer_size, u32* out_sent_count);


i32 platform_critsec_init    (critsec_t* critsec);
i32 platform_critsec_enter   (critsec_t* critsec);
i32 platform_critsec_leave   (critsec_t* critsec);
i32 platform_critsec_destroy (critsec_t* critsec);


i32 platform_condvar_init       (condvar_t* condvar);
i32 platform_condvar_wait       (condvar_t* condvar, critsec_t* critsec);
i32 platform_condvar_notify_any (condvar_t* condvar);
i32 platform_condvar_notify_all (condvar_t* condvar);
i32 platform_condvar_destroy    (condvar_t* condvar);


typedef struct State State;
typedef enum HTTP_STATUS
{
	HTTP_STATUS_CONTINUE              = 100,
	HTTP_STATUS_OK                    = 200,
	HTTP_STATUS_CREATED               = 201,
	HTTP_STATUS_BAD_REQUEST           = 400,
	HTTP_STATUS_UNAUTHORIZED          = 401,
	HTTP_STATUS_FORBIDDEN             = 403,
	HTTP_STATUS_NOT_FOUND             = 404,
	HTTP_STATUS_METHOD_NOT_ALLOWED    = 405,
	HTTP_STATUS_EXPECTATION_FAILED    = 417,
	HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
	HTTP_STATUS_NOT_IMPLEMENTED       = 501,
} HTTP_STATUS;

HTTP_STATUS platform_put_resource (State* state, Str0 resource_path, u32 resource_path_len, const u8* content, u32 content_size);
HTTP_STATUS platform_get_resource (State* state, Str0 resource_path, u32 resource_path_len, u8** out_content, u32* out_content_size);




static
void* _memory_alloc(size_t size, const char* __file__, int __line__)
{
	if(!size) return NULL;
	void* mem = platform_memory_alloc(size);
	if(mem == NULL)
	{
		PRINT_ERROR_FL(__file__, __line__, "memory allocation of size %zu failed", size);
		return NULL;
	}
	return mem;
}
#define memory_alloc(T, count) _memory_alloc(sizeof(T)*(count), __FILE__, __LINE__)


static
void _memory_free(void* addr, size_t size, const char* __file__, int __line__)
{
	if(!(addr && size)) return;
	if(platform_memory_free(addr, size) != 0)
	{
		PRINT_ERROR_FL(__file__, __line__, "memory deallocation of size %zu failed", size);
	}
}
#define memory_free(T, addr, count) _memory_free(addr, sizeof(T)*(count), __FILE__, __LINE__)
#define str0_free(str, len)          memory_free(char, str, (len)+1)


static
void* _memory_realloc(void* old_mem, size_t old_size, size_t new_size, const char* __file__, int __line__)
{
	void* new_mem = _memory_alloc(new_size, __file__, __line__);
	if(new_mem)
	{
		memcpy(new_mem, old_mem, MIN(old_size, new_size));
		_memory_free(old_mem, old_size, __file__, __line__);
	}
	return new_mem;
}
#define memory_realloc(T, oldm, oldc, newc) _memory_realloc(oldm, sizeof(T)*(oldc), sizeof(T)*(newc), __FILE__, __LINE__)

#endif // PLATFORM_H
