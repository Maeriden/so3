#include "platform.h"



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: MEMORY                             //
////////////////////////////////////////////////////////////
#include <stdlib.h>

void* platform_memory_alloc(size_t size)
{
	if(!size) return NULL;
	return calloc(size, 1);
	// void* mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	// if(mem == MAP_FAILED)
	// {
	// 	PRINT_ERROR_FL(__file__, __line__, "memory allocation of size %zu failed", size);
	// 	return NULL;
	// }
	// return mem;
}

i32 platform_memory_free(void* addr, size_t size)
{
	free(addr);
	return 0;
	// if(!(addr && size)) return 0;
	// return munmap(addr, size);
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: PRINTING                           //
////////////////////////////////////////////////////////////

static mutex_t* mutex_platform_print = NULL;

void platform_print(const_Str0 file, int line, u32 level, const_Str0 prefix, const_Str0 format, ...)
{
	State* state = &global_state;
	if(state->config.log_level < level)
		return;
	if(mutex_platform_print == NULL || pthread_mutex_lock(mutex_platform_print) == 0)
	{
		u32 pid = getpid();
		fprintf(stderr, "[%5u] %s:%i %s", pid, file, line, prefix);
		
		va_list args;
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		
		fputs("\e[39m\n", stderr);
		if(mutex_platform_print != NULL)
			pthread_mutex_unlock(mutex_platform_print);
	}
}

i32 platform_syslog(ipv4_addr_t address, const_Str0 userid, const_Str0 method, const_Str0 path, u32 minor, u32 status, u32 resource_size)
{
	// 80.116.239.218 - - [17/Jul/2011:18:29:19 +0100]  "GET /attivita/convegno1/libro1/gz/06-trio.ps.gz HTTP/1.0" 200 65536
	static const_Str0 strftime_format = "%d/%b/%Y:%H:%M:%S %z";
	time_t now   = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	char strftime_buffer[64] = {};
	strftime(strftime_buffer, sizeof(strftime_buffer), strftime_format, &tm);
	
	if(!userid || strlen(userid) == 0)
		userid = "-";
	
	
	syslog(LOG_DAEMON|LOG_INFO, "%hhu.%hhu.%hhu.%hhu - %s [%s] \"%s %s HTTP/1.%u\" %u %u",
	       address.oct[0], address.oct[1], address.oct[2], address.oct[3],
	       userid, strftime_buffer,
	       method, path, minor,
	       status, resource_size);
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: THREAD                             //
////////////////////////////////////////////////////////////

i32 platform_thread_init(thread_t* out_thread, thread_callback_t* callback, void* callback_arg)
{
	if(pthread_create(out_thread, NULL, callback, callback_arg) != 0)
		return -1;
	return 0;
}

i32 platform_thread_join(thread_t* thread)
{
	if(pthread_join(*thread, NULL) != 0)
		return -1;
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: CRITICAL SECTION                   //
////////////////////////////////////////////////////////////

i32 platform_critsec_init(critsec_t* out_critsec)
{
	if(pthread_mutex_init(out_critsec, NULL) != 0)
		return -1;
	return 0;
}

i32 platform_critsec_enter(critsec_t* critsec)
{
	if(pthread_mutex_lock(critsec) != 0)
		return -1;
	return 0;
}

i32 platform_critsec_leave(critsec_t* critsec)
{
	if(pthread_mutex_unlock(critsec) != 0)
		return -1;
	return 0;
}

i32 platform_critsec_destroy(critsec_t* critsec)
{
	if(pthread_mutex_destroy(critsec) != 0)
		return -1;
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: CONDITION VARIABLE                 //
////////////////////////////////////////////////////////////

i32 platform_condvar_init(condvar_t* out_condvar)
{
	if(pthread_cond_init(out_condvar, NULL) != 0)
		return -1;
	return 0;
}

i32 platform_condvar_wait(condvar_t* condvar, critsec_t* critsec)
{
	if(pthread_cond_wait(condvar, critsec) != 0)
		return -1;
	return 0;
}

i32 platform_condvar_notify_any(condvar_t* condvar)
{
	if(pthread_cond_signal(condvar) != 0)
		return -1;
	return 0;
}

i32 platform_condvar_notify_all(condvar_t* condvar)
{
	if(pthread_cond_broadcast(condvar) != 0)
		return -1;
	return 0;
}

i32 platform_condvar_destroy(condvar_t* condvar)
{
	if(pthread_cond_destroy(condvar) != 0)
		return -1;
	return 0;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: RECV/SEND                          //
////////////////////////////////////////////////////////////

i32 platform_recv(socket_t socket, u8* buffer, u32 buffer_size, u32* out_recv_count)
{
	*out_recv_count = 0;
	
	ssize_t recv_count = recv_nointr(socket, buffer, buffer_size, 0);
	if(recv_count == -1 && errno != ECONNRESET)
	{
		PRINT_ERROR("recv() failed: errno = %s", errno_as_string);
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
	
	i32 error = 0;
	u32 sent_total = 0;
	while(sent_total < buffer_size)
	{
		u8* remaining_data      = buffer      + sent_total;
		u32 remaining_data_size = buffer_size - sent_total;
		
		ssize_t sent_count = send_nointr(socket, remaining_data, remaining_data_size, MSG_NOSIGNAL);
		if(sent_count == -1)
		{
			if(errno != ECONNRESET && errno != EPIPE)
			{
				PRINT_ERROR("send() failed: errno = %s", errno_as_string);
				error = -1;
			}
			break;
		}
		
		if(sent_count == 0)
		{
			break;
		}
		
		sent_total += sent_count;
	}
	
	*out_sent_count = sent_total;
	return error;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: PUT RESOURCE                       //
////////////////////////////////////////////////////////////

static
i32 create_resource_path(Str0 full_path)
{
	ASSERT(full_path[0] == '/');
	u32 full_path_len = strlen(full_path);
	
	// NOTE: There SHOULD be no problems relative to PATH_MAX
	for(u32 i = 1; i < full_path_len; ++i)
	{
		if(full_path[i] == '/')
		{
			full_path[i] = 0;
			int error = mkdir(full_path, 00755);
			full_path[i] = '/';
			
			if(error && errno != EEXIST)
			{
				PRINT_ERROR("mkdir(%s) failed: errno = %s", full_path, errno_as_string);
				return -1;
			}
		}
	}
	return 0;
}

HTTP_STATUS platform_put_resource(State* state, Str0 full_path, const u8* content, u32 content_size)
{
	ASSERT(full_path != NULL);
	
	struct stat statbuf;
	if(stat(full_path, &statbuf) == 0)
	{
		if(S_ISDIR(statbuf.st_mode))
		{
			// Directory cannot be target of PUT
			return HTTP_STATUS_METHOD_NOT_ALLOWED;
		}
	}
	else if(errno != ENOENT)
	{
		PRINT_ERROR("stat(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	if(create_resource_path(full_path) != 0)
	{
		PRINT_ERROR("create_resource_path(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	int resource_fd = open_nointr(full_path, O_CREAT|O_WRONLY|O_TRUNC|O_CLOEXEC, 00644);
	if(resource_fd == -1)
	{
		PRINT_ERROR("open(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}

	// There can be no content; PUTing an empty file is a valid operation
	if(content && content_size)
	{
		if(fshlock_nointr(resource_fd) != 0)
		{
			PRINT_ERROR("flock(%s) failed", full_path);
			close(resource_fd);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
		
		ssize_t write_count = write_nointr(resource_fd, content, content_size);
		funlock_nointr(resource_fd);
		if(write_count != content_size)
		{
			PRINT_ERROR("write(%s) failed: errno = %s", full_path, errno_as_string);
			close(resource_fd);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
	}
	
	close(resource_fd);
	return HTTP_STATUS_CREATED;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: GET RESOURCE                       //
////////////////////////////////////////////////////////////

static
HTTP_STATUS get_directory_listing(State* state, int resource_fd, const_Str0 full_path, u8** out_content, u32* out_content_size)
{
	struct dirent** entries = NULL;
	int entries_count = scandirat(resource_fd, ".", &entries, NULL, alphasort);
	if(entries_count < 0)
	{
		PRINT_ERROR("scandir(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	if(entries_count == 0)
		return HTTP_STATUS_OK;
	
	u32 buffer_size = 0;
	for(u32 i = 0; i < entries_count; ++i)
	{
		buffer_size += strlen(entries[i]->d_name) + 1;
#if !DISABLE_SCANDIR_TRAILER
		if(entries[i]->d_type == DT_DIR)
			buffer_size += 1;
#endif
	}
	
	char* buffer = memory_alloc(char, buffer_size);
	if(!buffer)
	{
		for(u32 i = 0; i < entries_count; ++i)
			free(entries[i]);
		free(entries);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	char* name = buffer;
	for(u32 i = 0; i < entries_count; ++i)
	{
		u32 name_len = strlen(entries[i]->d_name);
		memcpy(name, entries[i]->d_name, name_len);
#if !DISABLE_SCANDIR_TRAILER
		if(entries[i]->d_type == DT_DIR)
			name[name_len++] = '/';
#endif
		name[name_len] = '\n';
		name += name_len + 1;
	}
	
	*out_content      = buffer;
	*out_content_size = buffer_size;
	
	for(u32 i = 0; i < entries_count; ++i)
		free(entries[i]);
	free(entries);
	return HTTP_STATUS_OK;
}

HTTP_STATUS platform_get_resource(State* state, Str0 full_path, u8** out_content, u32* out_content_size)
{
	ASSERT(full_path != NULL);
	*out_content      = NULL;
	*out_content_size = 0;
	
	int resource_fd = open_nointr(full_path, O_RDONLY|O_CLOEXEC, 0);
	if(resource_fd == -1)
	{
		if(errno == ENOENT)
			return HTTP_STATUS_NOT_FOUND;
		PRINT_ERROR("open(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	// NOTE: Closing the file releases the lock
	if(fshlock_nointr(resource_fd) != 0)
	{
		PRINT_ERROR("flock(%s) failed: errno = %s", full_path, errno_as_string);
		close(resource_fd);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	struct stat statbuf;
	if(fstat(resource_fd, &statbuf) != 0)
	{
		PRINT_ERROR("stat(%s) failed: errno = %s", full_path, errno_as_string);
		close(resource_fd);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	if(S_ISDIR(statbuf.st_mode))
	{
		i32 error = get_directory_listing(state, resource_fd, full_path, out_content, out_content_size);
		close(resource_fd);
		return error;
	}
	
	u32   resource_map_size = statbuf.st_size;
	void* resource_map      = mmap(NULL, resource_map_size, PROT_READ, MAP_PRIVATE, resource_fd, 0);
	funlock_nointr(resource_fd);
	close(resource_fd);
	if(resource_map == MAP_FAILED)
	{
		PRINT_ERROR("mmap(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	void* resource_data = memory_alloc(u8, resource_map_size);
	if(!resource_data)
	{
		munmap(resource_map, resource_map_size);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	memcpy(resource_data, resource_map, resource_map_size);
	munmap(resource_map, resource_map_size);
	
	*out_content      = resource_data;
	*out_content_size = resource_map_size;
	return HTTP_STATUS_OK;
}



////////////////////////////////////////////////////////////
// PLATFORM FUNCTIONS: RUN RESOURCE                       //
////////////////////////////////////////////////////////////

static
HTTP_STATUS get_command_result(process_t subproc, int subproc_stdout, u8** out_output, u32* out_output_size)
{	
	*out_output      = NULL;
	*out_output_size = 0;
	
	int child_status = 0;
	do
	{
		if(waitpid(subproc, &child_status, 0) == -1)
		{
			PRINT_ERROR("wait(%u) failed: errno = %s", (u32)subproc, errno_as_string);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
	} while(WIFEXITED(child_status) == 0 && WIFSIGNALED(child_status) == 0);
	
	if(WIFEXITED(child_status) == 0)
	{
		PRINT_ERROR("Command did not terminate naturally");
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	int output_size = 0;
	if(ioctl(subproc_stdout, FIONREAD, &output_size) != 0)
	{
		PRINT_ERROR("ioctl(FIONREAD) failed");
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	if(output_size > 0)
	{
		u8* output = memory_alloc(u8, output_size);
		if(!output)
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		
		if(read_nointr(subproc_stdout, output, output_size) != output_size)
		{
			PRINT_ERROR("read() failed: errno = %s", errno_as_string);
			memory_free(u8, output, output_size);
			return HTTP_STATUS_INTERNAL_SERVER_ERROR;
		}
		
		*out_output      = output;
		*out_output_size = output_size;
	}
	return HTTP_STATUS_OK;
}

HTTP_STATUS platform_run_resource(State* state, Str0 full_path, u8** out_output, u32* out_output_size)
{
	ASSERT(full_path != NULL);
	*out_output      = NULL;
	*out_output_size = 0;
	
	int resource_fd = open_nointr(full_path, O_PATH|O_CLOEXEC, 0);
	if(resource_fd == -1)
	{
		if(errno == ENOENT)
			return HTTP_STATUS_NOT_FOUND;
		PRINT_ERROR("open(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	struct stat statbuf;
	if(fstat(resource_fd, &statbuf) != 0)
	{
		ASSERT(errno != ENOENT);
		PRINT_ERROR("stat(%s) failed: errno = %s", full_path, errno_as_string);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	if(!S_ISREG(statbuf.st_mode))
	{
		close(resource_fd);
		// Let's just say we don't support executing a non-regular file
		return HTTP_STATUS_METHOD_NOT_ALLOWED;
	}
	
	if(access(full_path, X_OK) != 0)
	{
		PRINT_WARN("Requested execution of %s but the server does not have execute permission", full_path);
		close(resource_fd);
		// A non-executable file in the commands directory is a configuration error
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	// TODO: Create thread?
	int pipe_stdou[2];
	pipe(pipe_stdou);
	
	pid_t pid = fork();
	if(pid == -1)
	{
		PRINT_ERROR("fork() failed: errno = %s", errno_as_string);
		close(resource_fd);
		return HTTP_STATUS_INTERNAL_SERVER_ERROR;
	}
	
	if(pid == 0)
	{
		dup2(pipe_stdou[1], 1);
		dup2(pipe_stdou[1], 2);
		
		close(pipe_stdou[0]);
		close(pipe_stdou[1]);
		
		// FIXME: argv[0] is probably wrong? what are the rules for the first argument?
		char* argv[] = {full_path, NULL};
		fexecve(resource_fd, argv, environ);
		PRINT_ERROR("exec(%s) failed: errno = %s", full_path, errno_as_string);
		exit(EXIT_FAILURE);
	}
	close(resource_fd);
	close(pipe_stdou[1]);
	
	HTTP_STATUS result = get_command_result(pid, pipe_stdou[0], out_output, out_output_size);
	close(pipe_stdou[0]);
	return result;
}
