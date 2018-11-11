#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
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
		.log_level             = LOG_LEVEL_MAX,
	},
	.users_count = 0,
	.users       = NULL,

	.listen_socket_plain = -1,
	.listen_socket_crypt = -1,
	.slaves_count        = 0,
	.slaves              = NULL,
	.thread_pool         = NULL,
};

#ifndef CONFDIR
#define CONFDIR "/tmp/os3-1701014/conf"
#endif

#ifndef DOCSDIR
#define DOCSDIR "/tmp/os3-1701014/docs"
#endif

#ifndef LOGSDIR
#define LOGSDIR "/tmp/os3-1701014/logs"
#endif


#include "utils.c"
#include "linux-utils.c"
#include "linux-args.c"
#include "linux-platform.c"
#include "thread_pool.c"
#include "server.c"


ThreadPool global_thread_pool = {};


typedef struct ThreadTaskArgs
{
	State*      state;
	socket_t    socket;
	u16         listen_port;
	ipv4_addr_t address;
} ThreadTaskArgs;

static
void thread_pool_task(void* param)
{
	ThreadTaskArgs* args = param;
	State*      state       = args->state;
	int         socket      = args->socket;
	u16         listen_port = args->listen_port;
	ipv4_addr_t address     = args->address;
	memory_free(ThreadTaskArgs, args, 1);
	
	u32 encryption_key = 0;
	if(listen_port == state->config.listen_port_crypt)
	{
		srand(address.dec);
		encryption_key = rand();
	}
	server_serve_client(state, socket, encryption_key, address);
	shutdown(socket, SOCKET_SHUTDOWN_RW);
	close(socket);
}


static
void destroy_print_module(State* state)
{
	if(state->is_slave_process)
		return;
	if(mutex_platform_print == NULL)
		return;
	pthread_mutex_destroy(mutex_platform_print);
	munmap(mutex_platform_print, sizeof(pthread_mutex_t));
	mutex_platform_print = NULL;
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
	// NOTE: DO NOT MODIFY SLAVE FLAG
	
	thread_pool_destroy(state->thread_pool);
	state->thread_pool = NULL;
	
	for(u32 i = 0; i < state->slaves_count; ++i)
	{
		waitpid(state->slaves[i], NULL, 0);
	}
	memory_free(pid_t, state->slaves, state->slaves_count);
	state->slaves_count = 0;
	state->slaves       = NULL;
	
	for(u32 i = 0; i < state->users_count; ++i)
	{
		str0_free(state->users[i], strlen(state->users[i]));
	}
	memory_free(Str0, state->users, state->users_count);
	state->users_count = 0;
	state->users       = NULL;
	
	if(state->listen_socket_plain != -1)
		close(state->listen_socket_plain);
	if(state->listen_socket_crypt != -1)
		close(state->listen_socket_crypt);
	state->listen_socket_plain = -1;
	state->listen_socket_crypt = -1;
	
	if(state->config.documents_root)
		str0_free(state->config.documents_root, strlen(state->config.documents_root));
	state->config.documents_root = NULL;
}



static
i32 handle_connections(State* state)
{
	struct pollfd pollfds[2] = {};
	pollfds[0].fd = state->listen_socket_plain;
	pollfds[1].fd = state->listen_socket_crypt;
	pollfds[0].events = POLLIN | POLLRDHUP;
	pollfds[1].events = POLLIN | POLLRDHUP;
	
	u16 listen_ports[2] = {state->config.listen_port_plain, state->config.listen_port_crypt};
	
	b32 running = 1;
	while(running)
	{
		if(poll(pollfds, 2, -1) == -1)
		{
			if(errno == EINTR)
				continue;
			PRINT_ERROR("poll() failed");
			break;
		}
		
		for(u32 i = 0; i < ARRAY_COUNT(pollfds); ++i)
		{
			if(pollfds[i].revents & POLLHUP)
			{
				PRINT_DEBUG("POLLHUP %i", pollfds[i].fd);
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
				struct sockaddr_in sockaddr = {};
				socklen_t          addrlen  = sizeof(sockaddr);
				int client_socket = accept_nointr(pollfds[i].fd, &sockaddr, &addrlen, SOCK_CLOEXEC);
				if(client_socket == -1)
				{
					if(errno != EAGAIN)
						PRINT_ERROR("accept() failed: %s", errno_as_string);
					continue;
				}
				
				PRINT_DEBUG("POLLIN %i", (int)pollfds[i].fd);
				
				ThreadTask*     task = thread_pool_task;
				ThreadTaskArgs* args = memory_alloc(ThreadTaskArgs, 1);
				if(!args)
				{
					u8* addr = args->address.oct;
					PRINT_ERROR("Dropping connection to %hhu.%hhu.%hhu.%hhu", addr[0], addr[1], addr[2], addr[3]);
					shutdown(client_socket, SOCKET_SHUTDOWN_RW);
					close(client_socket);
					memory_free(ThreadTaskArgs, args, 1);
					continue;
				}
				args->state       = state;
				args->socket      = client_socket;
				args->listen_port = listen_ports[i];
				args->address.dec = sockaddr.sin_addr.s_addr;
				
				if(thread_pool_enqueue_task(state->thread_pool, task, args) != 0)
				{
					PRINT_ERROR("thread_pool_enqueue_task() failed");
					u8* addr = args->address.oct;
					PRINT_ERROR("Dropping connection to %hhu.%hhu.%hhu.%hhu", addr[0], addr[1], addr[2], addr[3]);
					shutdown(client_socket, SOCKET_SHUTDOWN_RW);
					close(client_socket);
					memory_free(ThreadTaskArgs, args, 1);
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
	*state->thread_pool = (ThreadPool){};
	if(thread_pool_init(state->thread_pool, 1+state->config.extra_threads_count) != 0)
		return -1;
	return 0;	
}


static
i32 init_subprocesses(State* state)
{
	if(state->config.extra_processes_count == 0)
		return 0;
	
	state->slaves = memory_alloc(pid_t, state->config.extra_processes_count);
	if(!state->slaves)
		return -1;
	
	for(u32 i = 0; i < state->config.extra_processes_count; ++i)
	{
		pid_t pid = fork();
		if(pid == -1)
		{
			PRINT_ERROR("fork() failed");
			for(u32 i = 0; i < state->slaves_count; ++i)
			{
				kill(state->slaves[i], SIGTERM);
				waitpid(state->slaves[i], NULL, 0);
			}
			memory_free(pid_t, state->slaves, state->config.extra_processes_count);
			state->slaves       = NULL;
			state->slaves_count = 0;
			return -1;
		}
		
		if(pid == 0)
		{
			state->is_slave_process = 1;
			memory_free(pid_t, state->slaves, state->config.extra_processes_count);
			state->slaves       = NULL;
			state->slaves_count = 0;
			// https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits
			if(prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) != 0)
				PRINT_ERROR("prctl(PR_SET_PDEATHSIG, SIGTERM) failed");
			return 0;
		}
		else
		{
			state->slaves[i] = pid;
			state->slaves_count += 1;
		}
	}
	return 0;
}


static
i32 init_listen_socket(int* out_socket, u16 port)
{
	char getaddrinfo_service[] = "00000";
	snprintf(getaddrinfo_service, sizeof(getaddrinfo_service), "%hu", port);
	
	struct addrinfo hints = {};
	hints.ai_family   = AF_INET  ;   // Allow IPv4
	hints.ai_socktype = SOCK_STREAM; // Specify a stream socket
	hints.ai_protocol = IPPROTO_TCP; // Specify the TCP protocol 
	hints.ai_flags    = AI_PASSIVE;  // Indicates the caller intends to use the returned socket address structure in a call to the bind function.
	
	struct addrinfo* addrinfo = NULL;
	if(getaddrinfo(NULL, getaddrinfo_service, &hints, &addrinfo) != 0)
	{
		PRINT_ERROR("getaddrinfo() failed: %m");
		return -1;
	}
	
	int listen_socket = socket(addrinfo->ai_family, addrinfo->ai_socktype|SOCK_NONBLOCK|SOCK_CLOEXEC, addrinfo->ai_protocol);
	if(listen_socket == -1)
	{
		PRINT_ERROR("socket() failed: %m");
		freeaddrinfo(addrinfo);
		return -1;
	}
	
	// Allow reuse of port immediately
	// DOUBT: Should we use SO_REUSEPORT since we have multiple accept threads?
	int enabled = 1;
	if(setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(int)) != 0)
	{
		PRINT_WARN("setsockopt() failed: %m");
	}
	
	if(bind(listen_socket, addrinfo->ai_addr, addrinfo->ai_addrlen) != 0)
	{
		PRINT_ERROR("bind() failed: %m");
		close(listen_socket);
		freeaddrinfo(addrinfo);
		return -1;
	}
	
	if(listen(listen_socket, 8) != 0)
	{
		PRINT_ERROR("listen() failed: %m");
		close(listen_socket);
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
	
	i32 error = parse_config_string(config_string, config_string_size, &state->config);
	memory_free(char, config_string, config_string_size);
	if(error)
	{
		PRINT_ERROR("parse_config_string() failed");
		return -1;
	}
	
	if(!state->config.documents_root)
		state->config.documents_root = str0_dup0(DOCSDIR);
	
	// global_log_level = state->config.log_level;
	
	return 0;
}


static
i32 init_state(State* state)
{
	state->reload = 0;
	state->is_slave_process = 0;
	
	state->config = (Configuration) {
		.listen_port_plain     = 8080,
		.listen_port_crypt     = 8081,
		.extra_processes_count = 0,
		.extra_threads_count   = 0,
		.disable_authorization = 0,
		.documents_root        = NULL,
		.log_level             = LOG_LEVEL_MAX,
	};
	state->users_count = 0;
	state->users       = NULL;
	
	state->listen_socket_plain = -1;
	state->listen_socket_crypt = -1;
	state->slaves_count = 0;
	state->slaves       = NULL;
	state->thread_pool  = &global_thread_pool;
	
	return 0;
}


static
void signal_action(int signal, siginfo_t* info, void* ucontext)
{
	PRINT_DEBUG("received signal %i", signal);
	State* state = &global_state;
	switch(signal)
	{
		case SIGHUP:
		{
			state->reload = 1;
		} break;
		
		case SIGQUIT:
		case SIGTERM:
		{
			state->reload = 0;
		} break;
		
		default:
		{
			ASSERT(0);
		}
	}
	
	shutdown(state->listen_socket_plain, SHUT_RDWR);
	shutdown(state->listen_socket_crypt, SHUT_RDWR);
}


static
i32 init_signal_handlers(State* state)
{
	// NOTE: Signal settings will be inherited by child processes and new threads
	struct sigaction action = {};
	action.sa_sigaction = signal_action;
	action.sa_flags = SA_SIGINFO;
	
	sigaction(SIGHUP,  &action, NULL);
	// sigaction(SIGINT,  &action, NULL);
	sigaction(SIGQUIT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	return 0;
}


static
i32 init_syslog()
{
	tzset();
	openlog(NULL, LOG_PERROR, LOG_DAEMON);
	return 0;
}


static
i32 init_daemon()
{
	if(daemon(1, 0) != 0)
	{
		PRINT_ERROR("daemon() failed");
		return -1;
	}
	return 0;
}


static
i32 init_print_module()
{
	if(mutex_platform_print != NULL)
		return 0;
	mutex_platform_print = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if(mutex_platform_print == MAP_FAILED)
	{
		PRINT_ERROR("mmap() failed");
		return -1;
	}
	pthread_mutexattr_t attrs;
	if(pthread_mutexattr_init(&attrs) != 0)
	{
		PRINT_ERROR("pthread_mutexattr_init() failed");
		return -1;
	}
	if(pthread_mutexattr_setpshared(&attrs, PTHREAD_PROCESS_SHARED) != 0)
	{
		PRINT_ERROR("pthread_mutexattr_setpshared() failed");
		pthread_mutexattr_destroy(&attrs);
		return -1;
	}
	if(pthread_mutex_init(mutex_platform_print, &attrs) != 0)
	{
		PRINT_ERROR("pthread_mutex_init() failed");
		pthread_mutexattr_destroy(&attrs);
		return -1;
	}
	pthread_mutexattr_destroy(&attrs);
	return 0;
}


int main(int argc, char** argv)
{
	CLIArgs* args  = &global_args;
	if(parse_args(argc, argv, args) != 0)
	{
		PRINT_ERROR("argp_parse() failed");
		return 1;
	}
	State* state = &global_state;
	
	if(init_print_module() != 0)
	{
		PRINT_ERROR("init_print_module() failed");
		return 1;
	}
	
	if(args->daemonize && init_daemon() != 0)
	{
		PRINT_ERROR("init_daemon() failed");
		return 1;
	}
	
	if(init_syslog() != 0)
	{
		PRINT_ERROR("init_syslog() failed");
		return 1;
	}
	
	if(init_signal_handlers(state) != 0)
	{
		PRINT_ERROR("init_signal_handlers() failed");
		return 1;
	}
	
	// BEGIN SERVER LOOP
	
	int result = 0;
	do {
		if(init_state(state) != 0)
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
		
		if(result == 0 && init_listen_socket(&state->listen_socket_plain, state->config.listen_port_plain) != 0)
		{
			PRINT_ERROR("init_listen_socket(%hu) failed", state->config.listen_port_plain);
			result = 1;
		}
		
		if(result == 0 && init_listen_socket(&state->listen_socket_crypt, state->config.listen_port_crypt) != 0)
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
	
	closelog();
	destroy_print_module(state);
	
	return result;
}
