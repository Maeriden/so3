#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#pragma comment(lib, "Ws2_32.lib")

#include <windows.h>
#include <ws2tcpip.h>

#include <stdlib.h>

#include "inih/ini.c"
#include "phr/picohttpparser.c"

#include "platform.h"


typedef struct
{
	u16  listen_port_plain;   
	u16  listen_port_crypt;
	u32  extra_processes_count;
	u32  extra_threads_count;
	b32  disable_authorization;
	Str0 documents_root;
	u32  log_level;
} Configuration;

typedef struct ThreadPool ThreadPool;

typedef struct State
{
	volatile b32 reload;
	b32          is_slave_process;

	Configuration config;
	u32           users_count;
	Str0*         users;

	socket_t    listen_socket_plain;
	socket_t    listen_socket_crypt;
	u32         slaves_count;
	process_t*  slaves;
	ThreadPool* thread_pool;

	// Not reset on restart
	HANDLE syslog_handle;
} State;

State global_state = {
	.reload = 0,
	.is_slave_process = 0,
	
	.config = {
		.listen_port_plain     = 8080,
		.listen_port_crypt     = 8081,
		.extra_processes_count = 0,
		.extra_threads_count   = 0,
		.disable_authorization = 0,
		.documents_root        = NULL,
	},
	.users_count = 0,
	.users       = NULL,

	.listen_socket_plain = INVALID_SOCKET,
	.listen_socket_crypt = INVALID_SOCKET,
	.slaves_count        = 0,
	.slaves              = NULL,
	.thread_pool         = NULL,

	.syslog_handle = INVALID_HANDLE_VALUE,
};

#ifndef CONFDIR
#define CONFDIR "./conf"
#endif

#ifndef DOCSDIR
#define DOCSDIR "./docs"
#endif

#ifndef LOGSDIR
#define LOGSDIR "./logs"
#endif


#include "win32-utils.c"
#include "utils.c"
#include "win32-args.c"
#include "win32-platform.c"
#include "thread_pool.c"
#include "server.c"


ThreadPool global_thread_pool = {0};


typedef struct ThreadTaskArgs
{
	State*   state;
	socket_t socket;
	u32      address;
	u16      port;
} ThreadTaskArgs;

static
void thread_pool_task(void* param)
{
	ThreadTaskArgs* args = param;
	State* state   = args->state;
	int    socket  = args->socket;
	u32    address = args->address;
	u16    port    = args->port;
	
	u32 encryption_key = 0;
	if(port == state->config.listen_port_crypt)
	{
		srand(address);
		encryption_key = rand();
	}
	server_serve_client(state, socket, encryption_key, (u8*)&address);
	shutdown(socket, SOCKET_SHUTDOWN_RW);
	closesocket(socket);
	
	memory_free(ThreadTaskArgs, args, 1);
}


static
void destroy_print_module()
{
	if(mutex_platform_print != NULL)
		CloseHandle(mutex_platform_print);
}


static
b32 should_exit(State* state)
{
	if(state->is_slave_process)
		return 1;
	return !state->reload;
}


static
void destroy_state(State* state)
{
	// NOTE: DO NOT MODIFY STATE TERMINATION FLAG

	// shutdown(state->listen_socket_plain, SHUT_RDWR);
	// shutdown(state->listen_socket_crypt, SHUT_RDWR);

	thread_pool_destroy(state->thread_pool);
	state->thread_pool = NULL;

	for(u32 i = 0; i < state->slaves_count; ++i)
	{
		WaitForSingleObject(state->slaves[i], INFINITE);
		CloseHandle(state->slaves[i]);
	}
	memory_free(HANDLE, state->slaves, state->slaves_count);
	state->slaves_count = 0;
	state->slaves       = NULL;

	for(u32 i = 0; i < state->users_count; ++i)
	{
		str0_free(state->users[i], strlen(state->users[i]));
	}
	memory_free(Str0, state->users, state->users_count);
	state->users_count = 0;
	state->users       = NULL;

	if(state->listen_socket_plain != INVALID_SOCKET)
		closesocket(state->listen_socket_plain);
	if(state->listen_socket_crypt != INVALID_SOCKET)
		closesocket(state->listen_socket_crypt);
	state->listen_socket_plain = INVALID_SOCKET;
	state->listen_socket_crypt = INVALID_SOCKET;

	if(state->config.documents_root)
		str0_free(state->config.documents_root, strlen(state->config.documents_root));
	state->config.documents_root = NULL;
}


static
i32 handle_connections(State* state)
{
	struct pollfd pollfds[2] = {0};
	pollfds[0].fd = state->listen_socket_plain;
	pollfds[1].fd = state->listen_socket_crypt;
	pollfds[0].events = POLLIN;
	pollfds[1].events = POLLIN;
	
	b32 running = 1;
	while(running)
	{
		if(WSAPoll(pollfds, ARRAY_COUNT(pollfds), -1) == SOCKET_ERROR)
		{
			PRINT_ERROR("WSAPoll() failed: %s", WSALastErrorAsString);
			break;
		}
	
		for(u32 i = 0; i < ARRAY_COUNT(pollfds); ++i)
		{
			if(pollfds[i].revents & POLLHUP)
			{
				PRINT_DEBUG("POLLHUP %i", (int)pollfds[i].fd);
#pragma warning(suppress : 4146)
				pollfds[i].fd = -pollfds[i].fd;

				// If the other fd is ignored, break
				if(pollfds[(i+1) % 2].fd < 0)
				{
					running = 0;
					break;
				}
			}
			else if(pollfds[i].revents & POLLIN)
			{
				struct sockaddr_in sockaddr = {0};
				socklen_t          addrlen  = sizeof(sockaddr);
				int client_socket = accept(pollfds[i].fd, (struct sockaddr*)&sockaddr, &addrlen);
				if(client_socket == -1)
				{
					PRINT_ERROR("accept() failed: %s", WSALastErrorAsString);
					continue;
				}
	
				PRINT_DEBUG("POLLIN %i", (int)pollfds[i].fd);
	
				ThreadTask*     task = thread_pool_task;
				ThreadTaskArgs* args = memory_alloc(ThreadTaskArgs, 1);
				if(!args)
				{
					u8* addr = (u8*)&sockaddr.sin_addr.s_addr;
					PRINT_ERROR("Dropping connection to %hhu.%hhu.%hhu.%hhu", addr[0], addr[1], addr[2], addr[3]);
					shutdown(client_socket, SOCKET_SHUTDOWN_RW);
					closesocket(client_socket);
					continue;
				}
				args->state   = state;
				args->socket  = client_socket;
				args->address = sockaddr.sin_addr.s_addr;
				args->port    = sockaddr.sin_port;
	
				if(thread_pool_enqueue_task(state->thread_pool, task, args) != 0)
				{
					PRINT_ERROR("thread_pool_start_job() failed");
					u8* addr = (u8*)&sockaddr.sin_addr.s_addr;
					PRINT_ERROR("Dropping connection to %hhu.%hhu.%hhu.%hhu", addr[0], addr[1], addr[2], addr[3]);
					shutdown(client_socket, SOCKET_SHUTDOWN_RW);
					closesocket(client_socket);
					running = 0;
				}
			}
		}
	}

	return 0;
}


static
i32 init_threads(State* state)
{
	*state->thread_pool = (ThreadPool){0};
	if(thread_pool_init(state->thread_pool, 1+state->config.extra_threads_count) != 0)
		return -1;
	return 0;	
}


static
i32 init_subprocesses(State* state)
{
	if(state->is_slave_process)
		return 0;
	if(state->config.extra_processes_count == 0)
		return 0;
	ASSERT(state->slaves_count == 0);

	// FIXME: GetModuleFileName must not fail ever
	char executable_path[1024] = {0};
	u32  executable_path_len = GetModuleFileNameA(NULL, executable_path, sizeof(executable_path));
	if(executable_path_len == 0 || executable_path_len == sizeof(executable_path))
	{
		PRINT_ERROR("GetModuleFileNameA() failed");
		return -1;
	}

	state->slaves = memory_alloc(HANDLE, state->config.extra_processes_count);
	if(!state->slaves)
		return -1;

	SECURITY_ATTRIBUTES pipes_attrs = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	for(u32 i = 0; i < state->config.extra_processes_count; ++i)
	{
		// https://docs.microsoft.com/en-us/windows/desktop/ipc/using-pipes
		// https://docs.microsoft.com/en-us/windows/desktop/ProcThread/creating-a-child-process-with-redirected-input-and-output
		HANDLE pipe_stdin[2];
		if(!CreatePipe(pipe_stdin, pipe_stdin+1, &pipes_attrs, 0))
		{
			PRINT_ERROR("CreatePipe() failed");
			goto init_subprocesses_cleanup;
		}

		// Do not inherit write end of pipe
		if(!SetHandleInformation(pipe_stdin[1], HANDLE_FLAG_INHERIT, 0))
		{
			PRINT_ERROR("SetHandleInformation() failed");
			CloseHandle(pipe_stdin[0]);
			CloseHandle(pipe_stdin[1]);
			goto init_subprocesses_cleanup;
		}

		STARTUPINFO si = {sizeof(si), 0};
		si.dwFlags = STARTF_USESTDHANDLES;
		si.hStdInput = pipe_stdin[0];
		PROCESS_INFORMATION pi = {0};
		if(!CreateProcessA(executable_path, "--slave", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
		{
			PRINT_ERROR("CreateProcessA() failed");
			CloseHandle(pipe_stdin[0]);
			CloseHandle(pipe_stdin[1]);
			goto init_subprocesses_cleanup;
		}
		CloseHandle(pi.hThread);
		CloseHandle(pipe_stdin[0]);

		DWORD write_count;
		WriteFile(pipe_stdin[1], &state->syslog_handle,       sizeof(state->syslog_handle),       &write_count, NULL);
		WriteFile(pipe_stdin[1], &state->listen_socket_plain, sizeof(state->listen_socket_plain), &write_count, NULL);
		WriteFile(pipe_stdin[1], &state->listen_socket_crypt, sizeof(state->listen_socket_crypt), &write_count, NULL);
		CloseHandle(pipe_stdin[1]);

		state->slaves[i] = pi.hProcess;
		state->slaves_count += 1;
	}
	return 0;

init_subprocesses_cleanup:
	for(u32 i = 0; i < state->slaves_count; ++i)
	{
		TerminateProcess(state->slaves[i], 15);
		WaitForSingleObject(state->slaves[i], INFINITE);
		CloseHandle(state->slaves[i]);
	}
	memory_free(HANDLE, state->slaves, state->config.extra_processes_count);
	state->slaves       = NULL;
	state->slaves_count = 0;
	return -1;
}


static
i32 init_listen_socket(State* state, socket_t* out_socket, u16 port)
{
	if(state->is_slave_process)
	{
		DWORD read_count;
		ReadFile(STDIN_FILENO, out_socket, sizeof(socket_t), &read_count, NULL);
		return 0;
	}

	char getaddrinfo_service[] = "00000";
	snprintf(getaddrinfo_service, sizeof(getaddrinfo_service), "%hu", port);

	struct addrinfo hints = {0};
	hints.ai_family   = AF_INET  ;   // Allow IPv4
	hints.ai_socktype = SOCK_STREAM; // Specify a stream socket
	hints.ai_protocol = IPPROTO_TCP; // Specify the TCP protocol 
	hints.ai_flags    = AI_PASSIVE;  // Indicates the caller intends to use the returned socket address structure in a call to the bind function.

	struct addrinfo* addrinfo = NULL;
	if(getaddrinfo(NULL, getaddrinfo_service, &hints, &addrinfo) != 0)
	{
		PRINT_ERROR("getaddrinfo() failed");
		return -1;
	}

	socket_t listen_socket = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
	if(listen_socket == INVALID_SOCKET)
	{
		PRINT_ERROR("socket() failed");
		freeaddrinfo(addrinfo);
		return -1;
	}

	if(bind(listen_socket, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
	{
		PRINT_ERROR("bind() failed");
		closesocket(listen_socket);
		freeaddrinfo(addrinfo);
		return -1;
	}

	// Allow reuse of port immediately
	int enabled = 1;
	if(setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&enabled, sizeof(int)) != 0)
	{
		PRINT_WARN("setsockopt() failed");
	}

	if(listen(listen_socket, 8) != 0)
	{
		PRINT_ERROR("listen() failed");
		closesocket(listen_socket);
		freeaddrinfo(addrinfo);
		return -1;
	}

	*out_socket = listen_socket;
	freeaddrinfo(addrinfo);
	return 0;
}


static
i32 init_users(State* state)
{
	const_Str0 path = CONFDIR"/users";
	u32   users_string_size = 0;
	char* users_string      = NULL;
	if(read_entire_file(path, &users_string, &users_string_size) != 0)
	{
		PRINT_ERROR("read_entire_file(%s) failed", path);
		return -1;
	}

	i32 error = parse_users_string(users_string, users_string_size,
		&state->users, &state->users_count);
	memory_free(char, users_string, users_string_size);
	if(error)
	{
		PRINT_ERROR("parse_users_string() failed");
		return -1;
	}

	return 0;
}


static
i32 init_config(State* state)
{
	const_Str0 path = CONFDIR"/config.ini";
	u32   config_string_size = 0;
	char* config_string      = NULL;
	if(read_entire_file(path, &config_string, &config_string_size) != 0)
	{
		PRINT_ERROR("read_entire_file(%s) failed", path);
		return -1;
	}

	state->config.listen_port_plain = 8080;
	state->config.listen_port_crypt = 8081;

	i32 error = parse_config_string(config_string, config_string_size, &state->config);
	memory_free(char, config_string, config_string_size);
	if(error)
	{
		PRINT_ERROR("parse_config_string() failed");
		return -1;
	}

	if(!state->config.documents_root)
		state->config.documents_root = str0_dup0(DOCSDIR);

	global_log_level = state->config.log_level;

	return 0;
}


static
i32 init_state(State* state, b32 is_slave)
{
	state->reload = 0;
	state->is_slave_process = is_slave;

	state->config = (Configuration) {
		.listen_port_plain     = 8080,
		.listen_port_crypt     = 8081,
		.extra_processes_count = 0,
		.extra_threads_count   = 0,
		.disable_authorization = 0,
		.documents_root        = NULL,
	};
	state->users_count = 0;
	state->users       = NULL;

	state->listen_socket_plain = INVALID_SOCKET;
	state->listen_socket_crypt = INVALID_SOCKET;
	state->slaves_count        = 0;
	state->slaves              = NULL;
	state->thread_pool         = &global_thread_pool;

	return 0;
}


static
BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
	PRINT_DEBUG("Received control event %i", dwCtrlType);

	State* state = &global_state;
	switch(dwCtrlType)
	{
	case CTRL_C_EVENT:
	{
		state->reload = 1;
	} break;

	case CTRL_BREAK_EVENT:
	{
		state->reload = 0;
	} break;

	case CTRL_CLOSE_EVENT:
	{
		state->reload = 0;
	} break;

	case CTRL_LOGOFF_EVENT:
	{
		state->reload = 0;
	} break;

	case CTRL_SHUTDOWN_EVENT:
	{
		state->reload = 0;
	} break;
	}

	shutdown(state->listen_socket_plain, SOCKET_SHUTDOWN_RW);
	shutdown(state->listen_socket_crypt, SOCKET_SHUTDOWN_RW);
	return TRUE;
}


static
i32 init_syslog(b32 is_slave_process, HANDLE* out_log_handle)
{
	_tzset();

	HANDLE log_handle;
	if(is_slave_process)
	{
		DWORD read_count;
		if(!ReadFile(STDIN_FILENO, &log_handle, sizeof(log_handle), &read_count, NULL))
		{
			PRINT_ERROR("ReadFile(STDIN_FILENO) failed");
			return -1;
		}
	}
	else
	{
		const_Str0 path = LOGSDIR"/syslog.log";
		SECURITY_ATTRIBUTES attrs = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
		log_handle = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, &attrs, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(log_handle == INVALID_HANDLE_VALUE)
		{
			PRINT_ERROR("CreateFileA(%s) failed: GLE = %s", path, LastErrorAsString);
			return -1;
		}
	}

	*out_log_handle = log_handle;
	return 0;
}


static
i32 init_winsock()
{
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		PRINT_ERROR("WSAStartup(2.2) failed");
		return -1;
	}
	return 0;
}


static
i32 init_print_module()
{
	mutex_attr_t attrs = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	mutex_platform_print = CreateMutexA(&attrs, FALSE, "Local\\os3-1701014-_print_generic_mutex");
	if(mutex_platform_print == NULL)
		return -1;
	return 0;
}


int main(int argc, char** argv)
{
	CLIArgs args  = {0};
	if(parse_args(argc, argv, &args) != 0)
	{
		PRINT_ERROR("parse_args() failed");
		return 1;
	}
	State* state = &global_state;
	state->is_slave_process = args.is_slave;

	if(init_print_module() != 0)
	{
		PRINT_ERROR("init_print_module() failed");
		return 1;
	}
	
	if(init_winsock() != 0)
	{
		PRINT_ERROR("init_winsock() failed");
		return 1;
	}
	
	if(init_syslog(state->is_slave_process, &state->syslog_handle) != 0)
	{
		PRINT_ERROR("init_syslog() failed");
		return 1;
	}
	
	if(SetConsoleCtrlHandler(console_ctrl_handler, TRUE) == 0)
	{
		PRINT_ERROR("SetConsoleCtrlHandler() failed");
		return 1;
	}
	
	// BEGIN SERVER LOOP
	
	int result = 0;
	do {
		if(init_state(state, state->is_slave_process) != 0)
		{
			PRINT_ERROR("init_state() failed");
			result = 1;
		}
		
		if(result == 0 && init_config(state) != 0)
		{
			PRINT_ERROR("init_config() failed");
			result = 1;
		}
		
		if(result == 0 && init_users(state) != 0)
		{
			PRINT_ERROR("init_users() failed");
			result = 1;
		}

		if(result == 0 && init_listen_socket(state, &state->listen_socket_plain, state->config.listen_port_plain) != 0)
		{
			PRINT_ERROR("init_listen_socket(%hu) failed", state->config.listen_port_plain);
			result = 1;
		}
		
		if(result == 0 && init_listen_socket(state, &state->listen_socket_crypt, state->config.listen_port_crypt) != 0)
		{
			PRINT_ERROR("init_listen_socket(%hu) failed", state->config.listen_port_crypt);
			result = 1;
		}
		
		if(result == 0 && init_subprocesses(state) != 0)
		{
			PRINT_ERROR("init_subprocesses() failed");
			result = 1;
		}
		
		if(result == 0 && init_threads(state) != 0)
		{
			PRINT_ERROR("init_threads() failed");
			result = 1;
		}
		
		// PRINT_DEBUG("Ready!");
		if(result == 0 && handle_connections(state) != 0)
		{
			PRINT_ERROR("wait_for_signal() failed");
			result = 1;
		}
		
		destroy_state(state);
	} while(result == 0 && !should_exit(state));
	
	// END SERVER LOOP
	
	WSACleanup();
	destroy_print_module();
	
	return result;
}
