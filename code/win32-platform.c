#include "platform.h"



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: MEMORY                             //
////////////////////////////////////////////////////////////
#include <stdlib.h>

void* platform_memory_alloc(size_t size)
{
	if(!size) return NULL;
	return calloc(size, 1);
}

void platform_memory_free(void* addr, size_t size)
{
	if(!(addr && size)) return;
	free(addr);
}

void* platform_memory_realloc(void* old_mem, size_t old_size, size_t new_size)
{
	void* new_mem = platform_memory_alloc(new_size);
	if(new_mem)
	{
		memcpy(new_mem, old_mem, MIN(old_size, new_size));
		platform_memory_free(old_mem, old_size);
	}
	return new_mem;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: PRINTING                           //
////////////////////////////////////////////////////////////

u32 global_log_level = 0;
static mutex_t mutex_platform_print = NULL;

void platform_print(const_Str0 file, int line, u32 level, const_Str0 prefix, const_Str0 format, ...)
{
	if(level > global_log_level)
		return;

	if(!IS_VALID_MUTEX(mutex_platform_print) || platform_mutex_acquire(&mutex_platform_print) == 0)
	{
		u32 pid = _getpid();
		fprintf(stderr, "[%5u] %s:%i %s", pid, file, line, prefix);

		va_list args;
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);

		fputs("\n", stderr);

		if(IS_VALID_MUTEX(mutex_platform_print))
			platform_mutex_release(&mutex_platform_print);
	}
}

i32 platform_syslog(u8 address[4], const_Str0 userid, const_Str0 method, const_Str0 path, u32 minor, u32 status, u32 resource_size)
{
	// 80.116.239.218 - - [17/Jul/2011:18:29:19 +0100]  "GET /attivita/convegno1/libro1/gz/06-trio.ps.gz HTTP/1.0" 200 65536
	static const_Str0 STRFTIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z";
	time_t now   = time(NULL);
	struct tm tm = {0};
	localtime_s(&tm, &now);
	char strftime_buffer[64] = {0};
	strftime(strftime_buffer, sizeof(strftime_buffer), STRFTIME_FORMAT, &tm);

	if(!userid || strlen(userid) == 0)
		userid = "-";

	static const_Str0 SYSLOG_FORMAT = "%s: %hhu.%hhu.%hhu.%hhu - %s [%s] \"%s %s HTTP/1.%u\" %u %u\n";
	u32 buffer_len = snprintf(NULL, 0, SYSLOG_FORMAT,
		__argv[0],
		address[0], address[1], address[2], address[3],
		userid, strftime_buffer,
		method, path, minor,
		status, resource_size);
	Str0 buffer = memory_alloc(char, buffer_len+1);
	if(!buffer)
		return -1;

	snprintf(buffer, buffer_len+1, SYSLOG_FORMAT,
		__argv[0],
		address[0], address[1], address[2], address[3],
		userid, strftime_buffer,
		method, path, minor,
		status, resource_size);

	if(WaitForSingleObject(mutex_platform_print, INFINITE) == WAIT_OBJECT_0)
	{
		State* state = &global_state;
		DWORD write_count;
		WriteFile(state->syslog_handle, buffer, buffer_len, &write_count, NULL);
		ReleaseMutex(mutex_platform_print);
	}
	else
	{
		PRINT_ERROR("WaitForSingleObject() failed");
	}
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: THREAD                             //
////////////////////////////////////////////////////////////

i32 platform_thread_init(thread_t* out_thread, thread_callback_t* callback, void* callback_arg)
{
	thread_t thread = CreateThread(NULL, 0, callback, callback_arg, 0, NULL);
	if(!IS_VALID_THREAD(thread))
		return -1;
	*out_thread = thread;
	return 0;
}

i32 platform_thread_join(thread_t* thread)
{
	switch(WaitForSingleObject(*thread, (DWORD)INFINITE)) {
	case WAIT_OBJECT_0  : return  0;
	case WAIT_ABANDONED : return  0;
	case WAIT_TIMEOUT   : return -1;
	case WAIT_FAILED    : return -1;
	} return -1;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: MUTEX                              //
////////////////////////////////////////////////////////////

i32 platform_mutex_attr_init(mutex_attr_t* attrs)
{
	*attrs = (SECURITY_ATTRIBUTES){sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	return 0;
}

i32 platform_mutex_attr_destroy(mutex_attr_t* attrs)
{
	return 0;
}

i32 platform_mutex_init(mutex_t* out_mutex, mutex_attr_t* attrs, const_Str0 name)
{
	mutex_t mutex = CreateMutexA(attrs, FALSE, name);
	if(!IS_VALID_MUTEX(mutex))
		return 1;
	*out_mutex = mutex;
	return 0;
}

i32 platform_mutex_acquire(mutex_t* mutex)
{
	switch(WaitForSingleObject(*mutex, (DWORD)INFINITE)) {
	case WAIT_OBJECT_0  : return  0;
	case WAIT_ABANDONED : return  0;
	case WAIT_TIMEOUT   : return -1;
	case WAIT_FAILED    : return -1;
	} return -1;
}

i32 platform_mutex_release(mutex_t* mutex)
{
	if(!ReleaseMutex(*mutex))
		return -1;
	return 0;
}

i32 platform_mutex_destroy(mutex_t* mutex)
{
	if(!CloseHandle(*mutex))
		return -1;
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: CRITICAL SECTION                   //
////////////////////////////////////////////////////////////

i32 platform_critsec_init(critsec_t* out_critsec, critsec_attr_t* attrs)
{
	// NOTE: Value from https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-initializecriticalsectionandspincount
	const DWORD busy_wait_ticks = (attrs != NULL) ? (*attrs) : 0x00000400;
	if(!InitializeCriticalSectionAndSpinCount(out_critsec, busy_wait_ticks))
		return -1;
	return 0;
}

i32 platform_critsec_enter(critsec_t* critsec)
{
	EnterCriticalSection(critsec);
	return 0;
}

i32 platform_critsec_leave(critsec_t* critsec)
{
	LeaveCriticalSection(critsec);
	return 0;
}

i32 platform_critsec_destroy(critsec_t* critsec)
{
	DeleteCriticalSection(critsec);
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: CONDITION VARIABLE                 //
////////////////////////////////////////////////////////////

i32 platform_condvar_init(condvar_t* out_condvar, condvar_attr_t* attrs)
{
	InitializeConditionVariable(out_condvar);
	return 0;
}

i32 platform_condvar_wait(condvar_t* condvar, critsec_t* critsec)
{
	if(!SleepConditionVariableCS(condvar, critsec, INFINITE))
		return -1;
	return 0;
}

i32 platform_condvar_notify_any(condvar_t* condvar)
{
	WakeConditionVariable(condvar);
	return 0;
}

i32 platform_condvar_notify_all(condvar_t* condvar)
{
	WakeAllConditionVariable(condvar);
	return 0;
}

i32 platform_condvar_destroy(condvar_t* condvar)
{
	// NOTE: Win32 does not seem to need condvar destruction
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: RECV/SEND                          //
////////////////////////////////////////////////////////////

i32 platform_recv(socket_t socket, u8* buffer, u32 buffer_size, u32* out_recv_count)
{
	*out_recv_count = 0;

	int recv_count = recv(socket, buffer, buffer_size, 0);
	if(recv_count == SOCKET_ERROR)
	{
		PRINT_ERROR("recv() failed: WSALE = %s", WSALastErrorAsString);
		return -1;
	}

	*out_recv_count = recv_count;
	return 0;
}

i32 platform_send(socket_t socket, u8* buffer, u32 buffer_size, u32* out_sent_count)
{
	*out_sent_count = 0;

	if(!(buffer && buffer_size))
		return 0;

	u32 sent_total = 0;
	while(sent_total < buffer_size)
	{
		u8* remaining_data      = buffer      + sent_total;
		u32 remaining_data_size = buffer_size - sent_total;

		int sent_count = send(socket, remaining_data, remaining_data_size, 0);
		if(sent_count == SOCKET_ERROR)
		{
			PRINT_ERROR("send() failed: WSALE = %s", WSALastErrorAsString);
			return -1;
		}

		if(sent_count == 0)
			break;

		sent_total += sent_count;
	}

	*out_sent_count = sent_total;
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: PUT RESOURCE                       //
////////////////////////////////////////////////////////////

static
i32 create_resource_path(Str0 full_path, u32 full_path_len)
{
	// TODO: Remove MAX_PATH limitation by using CreateDirectoryW()
	if(full_path_len >= 248)
	{
		PRINT_DEBUG("create_resource_path(%s) failed: path longer than 248 chars (%u)", full_path, full_path_len);
		return -1;
	}

	for(u32 i = 0; i < full_path_len; ++i)
	{
		if(full_path[i] == '/')
		{
			full_path[i] = 0;
			BOOL success = CreateDirectoryA(full_path, NULL);
			full_path[i] = '/';
			
			if(!success && GetLastError() != ERROR_ALREADY_EXISTS)
			{
				PRINT_ERROR("CreateDirectoryA(%s) failed: GLE = %s", full_path, LastErrorAsString);
				return -1;
			}
		}
	}
	return 0;
}

HTTP_STATUS platform_put_resource(State* state, Str0 resource_path, u32 resource_path_len, const u8* content, u32 content_size)
{
	ASSERT(resource_path != NULL);
	ASSERT(resource_path_len > 0);
	ASSERT(resource_path[resource_path_len-1] != '/');
	ASSERT(str0_beginswith0(resource_path, "/commands") == FALSE);


	Str0 full_path = str0_cat0(state->config.documents_root, resource_path);
	if(!full_path)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	u32 full_path_len = strlen(full_path);

	WIN32_FILE_ATTRIBUTE_DATA attrs;
	if(GetFileAttributesExA(full_path, GetFileExInfoStandard, &attrs))
	{
		if(attrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			// Directory cannot be target of PUT
			return HTTP_STATUS_METHOD_NOT_ALLOWED;
		}
	}
	else if(GetLastError() != ERROR_FILE_NOT_FOUND)
	{
		PRINT_ERROR("GetFileAttributesExA(%s) failed", full_path);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	if(create_resource_path(full_path, full_path_len) != 0)
	{
		PRINT_ERROR("create_resource_path(%s) failed", full_path);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	HANDLE resource_fd = CreateFileA(full_path, FILE_GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(resource_fd == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA(%s) failed: GLE = %s", full_path, LastErrorAsString);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	if(content && content_size)
	{
		if(!LockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh) != 0)
		{
			PRINT_ERROR("LockFile(%s) failed", full_path);
			CloseHandle(resource_fd);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}

		DWORD write_count;
		BOOL success = WriteFile(resource_fd, content, content_size, &write_count, NULL);
		UnlockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh);
		if(!success)
		{
			PRINT_ERROR("WriteFile(%s) failed", full_path);
			CloseHandle(resource_fd);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
	}

	CloseHandle(resource_fd);
	return HTTP_STATUS_CREATED;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: GET RESOURCE                       //
////////////////////////////////////////////////////////////

static
HTTP_STATUS get_directory_listing(const_Str0 path, u8** out_content, u32* out_content_size)
{
	struct dirent** entries = NULL;
	int entries_count = scandir(path, &entries, NULL, alphasort);
	if(entries_count < 0)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	if(entries_count == 0)
		return HTTP_STATUS_OK;

	u32 buffer_size = 0;
	for(i32 i = 0; i < entries_count; ++i)
	{
		buffer_size += strlen(entries[i]->d_name) + 1;
#if !DISABLE_SCANDIR_TRAILER
		if(entries[i]->d_attr & FILE_ATTRIBUTE_DIRECTORY)
			buffer_size += 1;
#endif
	}

	char* buffer = memory_alloc(char, buffer_size);
	if(!buffer)
	{
		for(i32 i = 0; i < entries_count; ++i)
			free(entries[i]);
		free(entries);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	char* name = buffer;
	for(i32 i = 0; i < entries_count; ++i)
	{
		u32 name_len = strlen(entries[i]->d_name);
		memcpy(name, entries[i]->d_name, name_len);
#if !DISABLE_SCANDIR_TRAILER
		if(entries[i]->d_attr & FILE_ATTRIBUTE_DIRECTORY)
			name[name_len++] = '/';
#endif
		name[name_len] = '\n';
		name += name_len + 1;
	}

	*out_content      = buffer;
	*out_content_size = buffer_size;

	for(i32 i = 0; i < entries_count; ++i)
		free(entries[i]);
	free(entries);
	return HTTP_STATUS_OK;
}

static
HTTP_STATUS get_command_result(process_t subproc, filedes_t subproc_stdout, u8** out_output, u32* out_output_size)
{
	WaitForSingleObject(subproc, INFINITE);

	DWORD read_avail;
	if(!PeekNamedPipe(subproc_stdout, NULL, 0, NULL, &read_avail, NULL))
	{
		PRINT_ERROR("PeekNamedPipe() failed");
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	if(read_avail == 0)
	{
		*out_output      = NULL;
		*out_output_size = 0;
		return HTTP_STATUS_OK;
	}

	u32 buffer_size = read_avail;
	u8* buffer = memory_alloc(u8, buffer_size);
	if(!buffer)
	{
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	DWORD read_total = 0;
	while(read_total < buffer_size)
	{
		u8* avail_buffer      = buffer      + read_total;
		u32 avail_buffer_size = buffer_size - read_total;

		DWORD read_count = 0;
		if(!ReadFile(subproc_stdout, avail_buffer, avail_buffer_size, &read_count, NULL))
		{
			PRINT_ERROR("ReadFile() failed: GLE = %s", LastErrorAsString);
			memory_free(u8, buffer, buffer_size);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
		read_total += read_count;
	}

	*out_output      = buffer;
	*out_output_size = buffer_size;
	return HTTP_STATUS_OK;
}

static
HTTP_STATUS run_command(State* state, Str0 resource_path, u32 resource_path_len, u8** out_output, u32* out_output_size)
{
	SECURITY_ATTRIBUTES pipes_attrs = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	HANDLE pipe_stdou[2];
	if(!CreatePipe(pipe_stdou, pipe_stdou+1, &pipes_attrs, 0))
	{
		PRINT_ERROR("CreatePipe() failed");
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	// Do not inherit read end of pipe
	if(!SetHandleInformation(pipe_stdou[0], HANDLE_FLAG_INHERIT, 0))
	{
		PRINT_ERROR("SetHandleInformation() failed");
		CloseHandle(pipe_stdou[0]);
		CloseHandle(pipe_stdou[1]);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	STARTUPINFO si = {sizeof(si), 0};
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = pipe_stdou[1];
	si.hStdError  = pipe_stdou[1];
	PROCESS_INFORMATION pi = {0};
	if(!CreateProcessA(resource_path, NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		PRINT_ERROR("CreateProcessA() failed");
		CloseHandle(pipe_stdou[0]);
		CloseHandle(pipe_stdou[1]);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	CloseHandle(pi.hThread);
	CloseHandle(pipe_stdou[1]);

	HTTP_STATUS status = get_command_result(pi.hProcess, pipe_stdou[0], out_output, out_output_size);
	CloseHandle(pipe_stdou[0]);
	CloseHandle(pi.hProcess);
	return status;
}

HTTP_STATUS platform_get_resource(State* state, Str0 resource_path, u32 resource_path_len, u8** out_content, u32* out_content_size)
{
	ASSERT(resource_path != NULL);
	ASSERT(resource_path_len > 0);
	ASSERT(resource_path[resource_path_len-1] != '/');

	if(str0_beginswith0(resource_path, "/commands"))
	{
		return run_command(state, resource_path, resource_path_len, out_content, out_content_size);
	}

	Str0 local_path = str0_cat0(state->config.documents_root, resource_path);
	if(!local_path)
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;

	WIN32_FILE_ATTRIBUTE_DATA attrs;
	if(!GetFileAttributesExA(local_path, GetFileExInfoStandard, &attrs))
	{
		if(GetLastError() == ERROR_FILE_NOT_FOUND)
			return HTTP_STATUS_NOT_FOUND;
		PRINT_ERROR("GetFileAttributesExA(%s) failed", local_path);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	if(attrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		HTTP_STATUS status = get_directory_listing(local_path, out_content, out_content_size);
		if(status)
			PRINT_ERROR("get_directory_listing(%s) failed", local_path);
		return status;
	}

	HANDLE resource_fd = CreateFileA(local_path, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(resource_fd == INVALID_HANDLE_VALUE)
	{
		if(GetLastError() == ERROR_FILE_NOT_FOUND)
			return HTTP_STATUS_NOT_FOUND;
		PRINT_ERROR("CreateFileA(%s) failed: GLE = %s", local_path, LastErrorAsString);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	if(!LockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh) != 0)
	{
		PRINT_ERROR("LockFile(%s) failed", local_path);
		CloseHandle(resource_fd);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	HANDLE map = CreateFileMappingA(resource_fd, NULL, PAGE_READONLY, attrs.nFileSizeHigh, attrs.nFileSizeLow, NULL);
	if(map == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileMappingA(%s) failed", local_path);
		UnlockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh);
		CloseHandle(resource_fd);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	LPVOID map_view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if(map_view == NULL)
	{
		PRINT_ERROR("MapViewOfFile(%s) failed", local_path);
		CloseHandle(map);
		UnlockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh);
		CloseHandle(resource_fd);
	}

	u32   resource_data_size = attrs.nFileSizeLow;
	void* resource_data      = memory_alloc(u8, resource_data_size);
	if(!resource_data)
	{
		UnmapViewOfFile(map_view);
		CloseHandle(map);
		UnlockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh);
		CloseHandle(resource_fd);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	memcpy(resource_data, map_view, resource_data_size);

	UnmapViewOfFile(map_view);
	CloseHandle(map);
	UnlockFile(resource_fd, 0, 0, attrs.nFileSizeLow, attrs.nFileSizeHigh);
	CloseHandle(resource_fd);

	*out_content_size = resource_data_size;
	*out_content      = resource_data;
	return HTTP_STATUS_OK;
}
