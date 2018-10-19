i32 platform_recv(int socket, u8** out_data, u32* out_data_size)
{
	u32 buffer_size = 4096;
	u8* buffer      = memory_alloc(u8, buffer_size);
	if(!buffer)
		return -1;
	
	ssize_t bytes_received_total = 0;
	while(1)
	{
		void*  available_buffer      = buffer      + bytes_received_total;
		size_t available_buffer_size = buffer_size - bytes_received_total;
		
		ssize_t bytes_received_count = read(socket, available_buffer, available_buffer_size);
		if(bytes_received_count == -1)
		{
			if(errno == EINTR)
				continue;
			PRINT_ERROR("read() failed");
			memory_free(u8, buffer, buffer_size);
			return RESULT_SERVER_ERROR;
		}
		
		if(bytes_received_count == 0)
			break; // End-of-File (socket shutdown)
		
		if(bytes_received_total + bytes_received_count < 0)
		{
			PRINT_ERROR("exceeded maximum message size");
			memory_free(u8, buffer, buffer_size);
			return RESULT_SERVER_ERROR;
		}
		
		bytes_received_total += bytes_received_count;
		
		// ASSERT(bytes_received_total <= buffer_size);
		if(bytes_received_total == buffer_size)
		{
			u32   new_buffer_size = buffer_size + 4096;
			void* new_buffer      = memory_realloc(u8, buffer, buffer_size, new_buffer_size);
			if(!new_buffer)
			{
				memory_free(u8, buffer, buffer_size);
				return RESULT_SERVER_ERROR;
			}
			buffer      = new_buffer;
			buffer_size = new_buffer_size;
		}
	}
	
	if(bytes_received_total == 0)
	{
		memory_free(u8, buffer, buffer_size);
		buffer      = NULL;
		buffer_size = 0;
		return RESULT_CLIENT_ERROR;
	}
	
	if(bytes_received_total < buffer_size)
	{
		// Shrink result to exact request length
		u32 final_buffer_size = bytes_received_total;
		u8* final_buffer      = memory_realloc(u8, buffer, buffer_size, final_buffer_size);
		if(!final_buffer)
		{
			memory_free(u8, buffer, buffer_size);
			return RESULT_SERVER_ERROR;
		}
		buffer      = final_buffer;
		buffer_size = final_buffer_size;
	}
	
	*out_data      = buffer;
	*out_data_size = buffer_size;
	return RESULT_SUCCESS;
}

i32 platform_send(int socket, u8* data, u32 data_size)
{
	if(!(data && data_size))
		return 0;
	
	ssize_t bytes_sent_total = 0;
	while(bytes_sent_total < data_size)
	{
		void*  remaining_data      = data      + bytes_sent_total;
		size_t remaining_data_size = data_size - bytes_sent_total;
		
		ssize_t bytes_sent_count = write(socket, remaining_data, remaining_data_size);
		if(bytes_sent_count == -1)
		{
			if(errno == EINTR)
				continue;
			PRINT_ERROR("write() failed");
			return RESULT_SERVER_ERROR;
		}
		ASSERT(bytes_sent_count > 0);
		bytes_sent_total += bytes_sent_count;
	}
	return 0;
}

i32 platform_check_authorization(Str0 auth_string, u32 auth_string_len, b32* out_authorized)
{
	State* state = &global_state;
	if(state->disable_authorization)
	{
		*out_authorized = 1;
		return 0;
	}
	
	*out_authorized = 0;
	if(auth_string)
	{
		for(u32 i = 0; i < state->users_count; ++i)
		{
			if(strcmp(state->users[i], auth_string) == 0)
			{
				*out_authorized = 1;
				break;
			}
		}
	}
	return 0;
}

i32 platform_put_resource(Str0 resource_path, u32 resource_path_len, const u8* content, u32 content_size)
{
	ASSERT(resource_path_len > 0);
	State* state = &global_state;
	
	if(resource_path_len == 1 && strcmp(resource_path, "/") == 0)
	{
		resource_path[0] = '.';
	}
	else
	{
		if(resource_path[0] == '/')
		{
			resource_path     += 1;
			resource_path_len -= 1;
		}
		if(resource_path[resource_path_len-1] == '/')
		{
			resource_path[resource_path_len-1] = 0;
			resource_path_len -= 1;
		}
	}
	
	int docsdir_fd = open_nointr(state->documents_root, O_PATH|O_DIRECTORY|O_CLOEXEC, 0);
	if(docsdir_fd == -1)
	{
		PRINT_ERROR("open(%s) failed", state->documents_root);
		return RESULT_SERVER_ERROR;
	}
	
	if(create_resource_path(docsdir_fd, resource_path, resource_path_len) != 0)
	{
		PRINT_ERROR("create_resource_path(%s/%s) failed", state->documents_root, resource_path);
		close(docsdir_fd);
		return RESULT_SERVER_ERROR;
	}
	
	int resource_fd = openat_nointr(docsdir_fd, resource_path, O_CREAT|O_WRONLY|O_TRUNC|O_CLOEXEC, 00644);
	close(docsdir_fd);
	if(resource_fd == -1)
	{
		PRINT_ERROR("open(%s/%s) failed", state->documents_root, resource_path);
		return RESULT_SERVER_ERROR;
	}
	
	if(flock_nointr(resource_fd) != 0)
	{
		PRINT_ERROR("flock(%s/%s) failed", state->documents_root, resource_path);
		close(resource_fd);
		return RESULT_SERVER_ERROR;
	}
	
	#if 0
	if(ftruncate(resource_fd, content_size) != 0)
	{
		PRINT_ERROR("ftruncate(%s/%s) failed", state->documents_root, resource_path);
		close(resource_fd);
		return RESULT_SERVER_ERROR;
	}
	
	void* resource_map = mmap(NULL, content_size, PROT_WRITE, MAP_SHARED, resource_fd, 0);
	close(resource_fd);
	if(resource_map == MAP_FAILED)
	{
		PRINT_ERROR("mmap(%s/%s) failed", state->documents_root, resource_path);
		return RESULT_SERVER_ERROR;
	}
	memcpy(resource_map, content, content_size);
	munmap(resource_map, content_size);
	#else
	ssize_t write_total = write_nointr(resource_fd, content, content_size);
	close(resource_fd);
	if(write_total != content_size)
	{
		PRINT_ERROR("write(%s/%s) failed", state->documents_root, resource_path);
		return RESULT_SERVER_ERROR;
	}
	#endif
	
	return RESULT_SUCCESS;
}


#if 0
static
i32 get_directory_listing(DIR* dir, u8** out_content, u32* out_content_size)
{
	ASSERT(dir != NULL);
	u32   buffer_size = 0;
	char* buffer      = NULL;
	
	for(struct dirent* entry = readdir(dir); entry != NULL; entry = readdir(dir))
	{
		u32 name_len = strlen(entry->d_name);
		u32 name_size = name_len + 1;
		if(entry->d_type == DT_DIR)
			name_size += 1;
		
		char* new_buffer = memory_realloc(char, buffer, buffer_size, buffer_size+name_size);
		if(!new_buffer)
		{
			memory_free(char, buffer, buffer_size);
			return RESULT_SERVER_ERROR;
		}
		buffer = new_buffer;
		
		char* new_name = buffer + buffer_size;
		memcpy(new_name, entry->d_name, name_len);
		if(entry->d_type == DT_DIR)
		{
			new_name[name_len] = '/';
			new_name[name_len+1] = '\n';
		}
		else
		{
			new_name[name_len] = '\n';
		}
		
		buffer_size += name_size;
	}
	
	*out_content      = buffer;
	*out_content_size = buffer_size;
	
	return RESULT_SUCCESS;
}
#else
static
i32 get_directory_listing(int dirfd, const_Str0 dir, u8** out_content, u32* out_content_size)
{
	struct dirent** entries = NULL;
	int entries_count = scandirat(dirfd, dir, &entries, NULL, alphasort);
	if(entries_count == -1)
		return RESULT_SERVER_ERROR;
	
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
		return RESULT_SERVER_ERROR;
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
	return RESULT_SUCCESS;
}
#endif


static
i32 get_command_result(pid_t child_pid, int child_stdout, u8** out_output, u32* out_output_size)
{	
	int child_status = 0;
	do
	{
		if(waitpid(child_pid, &child_status, 0) == -1)
		{
			PRINT_ERROR("wait(%u) failed", child_pid);
			return RESULT_SERVER_ERROR;
		}
	} while(WIFEXITED(child_status) == 0 && WIFSIGNALED(child_status) == 0);
	
	if(WIFEXITED(child_status) == 0)
	{
		PRINT_ERROR("command did not terminate naturally");
		return RESULT_SERVER_ERROR;
	}
	
	int output_size = 0;
	if(ioctl(child_stdout, FIONREAD, &output_size) != 0)
	{
		PRINT_ERROR("ioctl(FIONREAD) failed");
		return RESULT_SERVER_ERROR;
	}
	
	u8* output = memory_alloc(u8, output_size);
	if(!output)
		return RESULT_SERVER_ERROR;
	
	if(read_nointr(child_stdout, output, output_size) != output_size)
	{
		PRINT_ERROR("read() failed");
		memory_free(u8, output, output_size);
		return RESULT_SERVER_ERROR;
	}
	
	*out_output      = output;
	*out_output_size = output_size;
	return RESULT_SUCCESS;
}

static
i32 run_command(Str0 resource_path, u32 resource_path_len, u8** out_output, u32* out_output_size)
{
	State* state = &global_state;
	
	if(resource_path[0] == '/')
	{
		resource_path     += 1;
		resource_path_len -= 1;
	}
	if(resource_path[resource_path_len-1] == '/')
	{
		resource_path[resource_path_len-1] = 0;
		resource_path_len -= 1;
	}
	
	int docsdir_fd = open_nointr(state->documents_root, O_PATH|O_DIRECTORY|O_CLOEXEC, 0);
	if(docsdir_fd == -1)
	{
		PRINT_ERROR("open(%s) failed", state->documents_root);
		return RESULT_SERVER_ERROR;
	}
	
	int resource_fd = openat_nointr(docsdir_fd, resource_path, O_PATH|O_CLOEXEC, 0);
	close(docsdir_fd);
	if(resource_fd == -1)
	{
		if(errno == ENOENT)
			return RESULT_CLIENT_ERROR;
		PRINT_ERROR("open(%s/%s) failed", state->documents_root, resource_path);
		return RESULT_SERVER_ERROR;
	}
	
	// TODO: Create thread?
	int pipe_stdin[2];
	pipe(pipe_stdin);
	
	int pipe_stdout[2];
	pipe(pipe_stdout);
	
	pid_t pid = fork();
	if(pid == -1)
	{
		PRINT_ERROR("fork() failed");
		close(resource_fd);
		return RESULT_SERVER_ERROR;
	}
	
	if(pid == 0)
	{
		dup2(pipe_stdin[0],  0);
		dup2(pipe_stdout[1], 1);
		dup2(pipe_stdout[1], 2);
		
		close(pipe_stdin[0]), close(pipe_stdout[0]);
		close(pipe_stdin[1]), close(pipe_stdout[1]);
		
		// TODO: Support command arguments
		// FIXME: argv[0] is probably wrong? what are the rules for the first argument?
		char* argv[2] = {resource_path, NULL};
		// char* argv[1] = {NULL};
		fexecve(resource_fd, argv, environ);
		PRINT_ERROR("exec(%s/%s) failed", state->documents_root, resource_path);
		exit(EXIT_FAILURE);
	}
	close(resource_fd);
	close(pipe_stdin[0]), close(pipe_stdout[1]);
	
	i32 result = get_command_result(pid, pipe_stdout[0], out_output, out_output_size);
	close(pipe_stdin[1]), close(pipe_stdout[0]);
	return result;
}

i32 platform_get_resource(Str0 resource_path, u32 resource_path_len, u8** out_content, u32* out_content_size)
{
	ASSERT(resource_path_len > 0);
	State* state = &global_state;
	
	if(str0_beginswith0(resource_path, "/commands"))
	{
		return run_command(resource_path, resource_path_len, out_content, out_content_size);
	}
	
	if(resource_path_len == 1 && strcmp(resource_path, "/") == 0)
	{
		resource_path[0] = '.';
	}
	else
	{
		if(resource_path[0] == '/')
		{
			resource_path     += 1;
			resource_path_len -= 1;
		}
		if(resource_path[resource_path_len-1] == '/')
		{
			resource_path[resource_path_len-1] = 0;
			resource_path_len -= 1;
		}
	}
	
	int docsdir_fd = open_nointr(state->documents_root, O_RDONLY|O_DIRECTORY|O_PATH|O_CLOEXEC, 0);
	if(docsdir_fd == -1)
	{
		PRINT_ERROR("open(%s) failed", state->documents_root);
		return RESULT_SERVER_ERROR;
	}
	
	int resource_fd = openat_nointr(docsdir_fd, resource_path, O_RDONLY|O_CLOEXEC, 0);
	close(docsdir_fd);
	if(resource_fd == -1)
	{
		if(errno == ENOENT)
			return RESULT_CLIENT_ERROR;
		PRINT_ERROR("open(%s/%s) failed", state->documents_root, resource_path);
		return RESULT_SERVER_ERROR;
	}
	
	// NOTE: Closing the file releases the lock
	if(flock_nointr(resource_fd) != 0)
	{
		PRINT_ERROR("flock(%s/%s) failed", state->documents_root, resource_path);
		close(resource_fd);
		return RESULT_SERVER_ERROR;
	}
	
	struct stat statbuf = {};
	if(fstat(resource_fd, &statbuf) != 0)
	{
		PRINT_ERROR("stat(%s/%s) failed", state->documents_root, resource_path);
		close(resource_fd);
		return RESULT_SERVER_ERROR;
	}
	
	if(S_ISDIR(statbuf.st_mode))
	{
		i32 error = get_directory_listing(resource_fd, ".", out_content, out_content_size);
		close(resource_fd);
		if(error)
			PRINT_ERROR("scandirat(%s/%s) failed", state->documents_root, resource_path);
		return error;
	}
	
	u32   resource_data_size = statbuf.st_size;
	void* resource_data      = mmap(NULL, resource_data_size, PROT_READ, MAP_PRIVATE, resource_fd, 0);
	close(resource_fd);
	if(resource_data == MAP_FAILED)
	{
		PRINT_ERROR("mmap(%s/%s) failed: %m", state->documents_root, resource_path);
		return RESULT_SERVER_ERROR;
	}
	
	*out_content_size = resource_data_size;
	*out_content      = resource_data;
	return RESULT_SUCCESS;
}

i32 platform_syslog(u8 address[4], const_Str0 userid, const_Str0 method, const_Str0 path, u32 minor, u32 status, u32 resource_size)
{
	// 80.116.239.218 - - [17/Jul/2011:18:29:19 +0100]  "GET /attivita/convegno1/libro1/gz/06-trio.ps.gz HTTP/1.0" 200 65536
	static const_Str0 strftime_format = "%d/%b/%Y:%H:%M:%S %z";
	time_t now   = time(NULL);
	struct tm tm = {};
	localtime_r(&now, &tm);
	char strftime_buffer[64] = {};
	strftime(strftime_buffer, sizeof(strftime_buffer), strftime_format, &tm);
	
	if(!userid || strlen(userid) == 0)
		userid = "-";
	
	
	if(pthread_mutex_lock(_print_generic_mutex) == 0)
	{
		syslog(LOG_DAEMON|LOG_INFO, "%hhu.%hhu.%hhu.%hhu - %s [%s] \"%s %s HTTP/1.%u\" %u %u",
		       address[0], address[1], address[2], address[3],
		       userid, strftime_buffer,
		       method, path, minor,
		       status, resource_size);
		pthread_mutex_unlock(_print_generic_mutex);
	}
	else
	{
		PRINT_ERROR("pthread_mutex_lock() failed");
	}
	return 0;
}
