#include <assert.h>
#define ASSERT(c) assert(c)
#define ARRAY_COUNT(a) ( sizeof(a) / sizeof(*a) )


u32 global_log_level = 0;
static pthread_mutex_t* _print_generic_mutex = NULL;

void init_print_module()
{
	if(_print_generic_mutex)
		return;
	_print_generic_mutex = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	ASSERT(_print_generic_mutex != MAP_FAILED);
	pthread_mutexattr_t attrs;
	pthread_mutexattr_init(&attrs);
	pthread_mutexattr_setpshared(&attrs, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(_print_generic_mutex, &attrs);
	pthread_mutexattr_destroy(&attrs);
}

void free_print_module()
{
	if(!_print_generic_mutex)
		return;
	pthread_mutex_destroy(_print_generic_mutex);
	munmap(_print_generic_mutex, sizeof(pthread_mutex_t));
	_print_generic_mutex = NULL;
}


void _print_generic(const char* file, int line, u32 level, const char* prefix, const char* format, ...)
{
	if(level > global_log_level)
		return;
	if(pthread_mutex_lock(_print_generic_mutex) == 0)
	{
		u32 pid = getpid();
		fprintf(stderr, "[%5u] %s:%i %s", pid, file, line, prefix);
		
		va_list args;
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		
		fputs("\e[39m\n", stderr);
		pthread_mutex_unlock(_print_generic_mutex);
	}
}

#define RESULT_SUCCESS 0
#define RESULT_SERVER_ERROR -1
#define RESULT_CLIENT_ERROR -2

#define PRINT_ERROR_FL(F, L, ...) _print_generic(F, L, 1, "\e[31m[EE] ", __VA_ARGS__)
#define PRINT_WARN_FL(F, L, ...)  _print_generic(F, L, 2, "\e[33m[WW] ", __VA_ARGS__)
#define PRINT_DEBUG_FL(F, L, ...) _print_generic(F, L, 3, "\e[32m[DD] ", __VA_ARGS__)

#define PRINT_ERROR(...) PRINT_ERROR_FL(__FILE__, __LINE__, __VA_ARGS__)
#define PRINT_WARN(...)  PRINT_WARN_FL (__FILE__, __LINE__, __VA_ARGS__)
#define PRINT_DEBUG(...) PRINT_DEBUG_FL(__FILE__, __LINE__, __VA_ARGS__)

#define MIN(a, b) ( (a) < (b) ? (a) : (b) )


const Str0 errno_as_string(int err)
{
	switch(err) {
		case EPERM           : return "EPERM";           //   1     /* Operation not permitted */
		case ENOENT          : return "ENOENT";          //   2     /* No such file or directory */
		case ESRCH           : return "ESRCH";           //   3     /* No such process */
		case EINTR           : return "EINTR";           //   4     /* Interrupted system call */
		case EIO             : return "EIO";             //   5     /* I/O error */
		case ENXIO           : return "ENXIO";           //   6     /* No such device or address */
		case E2BIG           : return "E2BIG";           //   7     /* Argument list too long */
		case ENOEXEC         : return "ENOEXEC";         //   8     /* Exec format error */
		case EBADF           : return "EBADF";           //   9     /* Bad file number */
		case ECHILD          : return "ECHILD";          //  10     /* No child processes */
		case EAGAIN          : return "EAGAIN";          //  11     /* Try again */
		case ENOMEM          : return "ENOMEM";          //  12     /* Out of memory */
		case EACCES          : return "EACCES";          //  13     /* Permission denied */
		case EFAULT          : return "EFAULT";          //  14     /* Bad address */
		case ENOTBLK         : return "ENOTBLK";         //  15     /* Block device required */
		case EBUSY           : return "EBUSY";           //  16     /* Device or resource busy */
		case EEXIST          : return "EEXIST";          //  17     /* File exists */
		case EXDEV           : return "EXDEV";           //  18     /* Cross-device link */
		case ENODEV          : return "ENODEV";          //  19     /* No such device */
		case ENOTDIR         : return "ENOTDIR";         //  20     /* Not a directory */
		case EISDIR          : return "EISDIR";          //  21     /* Is a directory */
		case EINVAL          : return "EINVAL";          //  22     /* Invalid argument */
		case ENFILE          : return "ENFILE";          //  23     /* File table overflow */
		case EMFILE          : return "EMFILE";          //  24     /* Too many open files */
		case ENOTTY          : return "ENOTTY";          //  25     /* Not a typewriter */
		case ETXTBSY         : return "ETXTBSY";         //  26     /* Text file busy */
		case EFBIG           : return "EFBIG";           //  27     /* File too large */
		case ENOSPC          : return "ENOSPC";          //  28     /* No space left on device */
		case ESPIPE          : return "ESPIPE";          //  29     /* Illegal seek */
		case EROFS           : return "EROFS";           //  30     /* Read-only file system */
		case EMLINK          : return "EMLINK";          //  31     /* Too many links */
		case EPIPE           : return "EPIPE";           //  32     /* Broken pipe */
		case EDOM            : return "EDOM";            //  33     /* Math argument out of domain of func */
		case ERANGE          : return "ERANGE";          //  34     /* Math result not representable */
		
		case EDEADLK         : return "EDEADLK";         //  35     /* Resource deadlock would occur */
		case ENAMETOOLONG    : return "ENAMETOOLONG";    //  36     /* File name too long */
		case ENOLCK          : return "ENOLCK";          //  37     /* No record locks available */
		
		case ENOSYS          : return "ENOSYS";          //  38     /* Invalid system call number */
		
		case ENOTEMPTY       : return "ENOTEMPTY";       //  39     /* Directory not empty */
		case ELOOP           : return "ELOOP";           //  40     /* Too many symbolic links encountered */
		// case EWOULDBLOCK     : return "EWOULDBLOCK";     //  EAGAIN /* Operation would block */
		case ENOMSG          : return "ENOMSG";          //  42     /* No message of desired type */
		case EIDRM           : return "EIDRM";           //  43     /* Identifier removed */
		case ECHRNG          : return "ECHRNG";          //  44     /* Channel number out of range */
		case EL2NSYNC        : return "EL2NSYNC";        //  45     /* Level 2 not synchronized */
		case EL3HLT          : return "EL3HLT";          //  46     /* Level 3 halted */
		case EL3RST          : return "EL3RST";          //  47     /* Level 3 reset */
		case ELNRNG          : return "ELNRNG";          //  48     /* Link number out of range */
		case EUNATCH         : return "EUNATCH";         //  49     /* Protocol driver not attached */
		case ENOCSI          : return "ENOCSI";          //  50     /* No CSI structure available */
		case EL2HLT          : return "EL2HLT";          //  51     /* Level 2 halted */
		case EBADE           : return "EBADE";           //  52     /* Invalid exchange */
		case EBADR           : return "EBADR";           //  53     /* Invalid request descriptor */
		case EXFULL          : return "EXFULL";          //  54     /* Exchange full */
		case ENOANO          : return "ENOANO";          //  55     /* No anode */
		case EBADRQC         : return "EBADRQC";         //  56     /* Invalid request code */
		case EBADSLT         : return "EBADSLT";         //  57     /* Invalid slot */
		
		// case EDEADLOCK       : return "EDEADLOCK";       // EDEADLK
		
		case EBFONT          : return "EBFONT";          //  59     /* Bad font file format */
		case ENOSTR          : return "ENOSTR";          //  60     /* Device not a stream */
		case ENODATA         : return "ENODATA";         //  61     /* No data available */
		case ETIME           : return "ETIME";           //  62     /* Timer expired */
		case ENOSR           : return "ENOSR";           //  63     /* Out of streams resources */
		case ENONET          : return "ENONET";          //  64     /* Machine is not on the network */
		case ENOPKG          : return "ENOPKG";          //  65     /* Package not installed */
		case EREMOTE         : return "EREMOTE";         //  66     /* Object is remote */
		case ENOLINK         : return "ENOLINK";         //  67     /* Link has been severed */
		case EADV            : return "EADV";            //  68     /* Advertise error */
		case ESRMNT          : return "ESRMNT";          //  69     /* Srmount error */
		case ECOMM           : return "ECOMM";           //  70     /* Communication error on send */
		case EPROTO          : return "EPROTO";          //  71     /* Protocol error */
		case EMULTIHOP       : return "EMULTIHOP";       //  72     /* Multihop attempted */
		case EDOTDOT         : return "EDOTDOT";         //  73     /* RFS specific error */
		case EBADMSG         : return "EBADMSG";         //  74     /* Not a data message */
		case EOVERFLOW       : return "EOVERFLOW";       //  75     /* Value too large for defined data type */
		case ENOTUNIQ        : return "ENOTUNIQ";        //  76     /* Name not unique on network */
		case EBADFD          : return "EBADFD";          //  77     /* File descriptor in bad state */
		case EREMCHG         : return "EREMCHG";         //  78     /* Remote address changed */
		case ELIBACC         : return "ELIBACC";         //  79     /* Can not access a needed shared library */
		case ELIBBAD         : return "ELIBBAD";         //  80     /* Accessing a corrupted shared library */
		case ELIBSCN         : return "ELIBSCN";         //  81     /* .lib section in a.out corrupted */
		case ELIBMAX         : return "ELIBMAX";         //  82     /* Attempting to link in too many shared libraries */
		case ELIBEXEC        : return "ELIBEXEC";        //  83     /* Cannot exec a shared library directly */
		case EILSEQ          : return "EILSEQ";          //  84     /* Illegal byte sequence */
		case ERESTART        : return "ERESTART";        //  85     /* Interrupted system call should be restarted */
		case ESTRPIPE        : return "ESTRPIPE";        //  86     /* Streams pipe error */
		case EUSERS          : return "EUSERS";          //  87     /* Too many users */
		case ENOTSOCK        : return "ENOTSOCK";        //  88     /* Socket operation on non-socket */
		case EDESTADDRREQ    : return "EDESTADDRREQ";    //  89     /* Destination address required */
		case EMSGSIZE        : return "EMSGSIZE";        //  90     /* Message too long */
		case EPROTOTYPE      : return "EPROTOTYPE";      //  91     /* Protocol wrong type for socket */
		case ENOPROTOOPT     : return "ENOPROTOOPT";     //  92     /* Protocol not available */
		case EPROTONOSUPPORT : return "EPROTONOSUPPORT"; //  93     /* Protocol not supported */
		case ESOCKTNOSUPPORT : return "ESOCKTNOSUPPORT"; //  94     /* Socket type not supported */
		case EOPNOTSUPP      : return "EOPNOTSUPP";      //  95     /* Operation not supported on transport endpoint */
		case EPFNOSUPPORT    : return "EPFNOSUPPORT";    //  96     /* Protocol family not supported */
		case EAFNOSUPPORT    : return "EAFNOSUPPORT";    //  97     /* Address family not supported by protocol */
		case EADDRINUSE      : return "EADDRINUSE";      //  98     /* Address already in use */
		case EADDRNOTAVAIL   : return "EADDRNOTAVAIL";   //  99     /* Cannot assign requested address */
		case ENETDOWN        : return "ENETDOWN";        // 100     /* Network is down */
		case ENETUNREACH     : return "ENETUNREACH";     // 101     /* Network is unreachable */
		case ENETRESET       : return "ENETRESET";       // 102     /* Network dropped connection because of reset */
		case ECONNABORTED    : return "ECONNABORTED";    // 103     /* Software caused connection abort */
		case ECONNRESET      : return "ECONNRESET";      // 104     /* Connection reset by peer */
		case ENOBUFS         : return "ENOBUFS";         // 105     /* No buffer space available */
		case EISCONN         : return "EISCONN";         // 106     /* Transport endpoint is already connected */
		case ENOTCONN        : return "ENOTCONN";        // 107     /* Transport endpoint is not connected */
		case ESHUTDOWN       : return "ESHUTDOWN";       // 108     /* Cannot send after transport endpoint shutdown */
		case ETOOMANYREFS    : return "ETOOMANYREFS";    // 109     /* Too many references: cannot splice */
		case ETIMEDOUT       : return "ETIMEDOUT";       // 110     /* Connection timed out */
		case ECONNREFUSED    : return "ECONNREFUSED";    // 111     /* Connection refused */
		case EHOSTDOWN       : return "EHOSTDOWN";       // 112     /* Host is down */
		case EHOSTUNREACH    : return "EHOSTUNREACH";    // 113     /* No route to host */
		case EALREADY        : return "EALREADY";        // 114     /* Operation already in progress */
		case EINPROGRESS     : return "EINPROGRESS";     // 115     /* Operation now in progress */
		case ESTALE          : return "ESTALE";          // 116     /* Stale file handle */
		case EUCLEAN         : return "EUCLEAN";         // 117     /* Structure needs cleaning */
		case ENOTNAM         : return "ENOTNAM";         // 118     /* Not a XENIX named type file */
		case ENAVAIL         : return "ENAVAIL";         // 119     /* No XENIX semaphores available */
		case EISNAM          : return "EISNAM";          // 120     /* Is a named type file */
		case EREMOTEIO       : return "EREMOTEIO";       // 121     /* Remote I/O error */
		case EDQUOT          : return "EDQUOT";          // 122     /* Quota exceeded */
		
		case ENOMEDIUM       : return "ENOMEDIUM";       // 123     /* No medium found */
		case EMEDIUMTYPE     : return "EMEDIUMTYPE";     // 124     /* Wrong medium type */
		case ECANCELED       : return "ECANCELED";       // 125     /* Operation Canceled */
		case ENOKEY          : return "ENOKEY";          // 126     /* Required key not available */
		case EKEYEXPIRED     : return "EKEYEXPIRED";     // 127     /* Key has expired */
		case EKEYREVOKED     : return "EKEYREVOKED";     // 128     /* Key has been revoked */
		case EKEYREJECTED    : return "EKEYREJECTED";    // 129     /* Key was rejected by service */
		
		/* for robust mutexes */
		case EOWNERDEAD      : return "EOWNERDEAD";      // 130     /* Owner died */
		case ENOTRECOVERABLE : return "ENOTRECOVERABLE"; // 131     /* State not recoverable */
		
		case ERFKILL         : return "ERFKILL";         // 132     /* Operation not possible due to RF-kill */
		
		case EHWPOISON       : return "EHWPOISON";       // 133     /* Memory page has hardware error */
		
		// case ENOTSUP         : return "ENOTSUP";         // EOPNOTSUPP
	} return "";
}


void* _memory_alloc(size_t size, const char* __file__, int __line__)
{
	if(!size) return NULL;
	void* mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(mem == MAP_FAILED)
	{
		PRINT_ERROR_FL(__file__, __line__, "memory allocation of size %zu failed", size);
		return NULL;
	}
	return mem;
}
#define memory_alloc(T, count) _memory_alloc(sizeof(T)*(count), __FILE__, __LINE__)


void _memory_free(void* addr, size_t size, const char* __file__, int __line__)
{
	if(!(addr && size)) return;
	if(munmap(addr, size) != 0)
	{
		PRINT_ERROR_FL(__file__, __line__, "memory deallocation of size %zu failed", size);
	}
}
#define memory_free(T, addr, count) _memory_free(addr, sizeof(T)*(count), __FILE__, __LINE__)
#define str0_free(str, len) memory_free(char, str, (len)+1)


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


Str0 _strN_dup0(const char* str, u32 len, const char* __file__, int __line__)
{
	Str0 dup = _memory_alloc(len+1, __file__, __line__);
	if(dup)
		memcpy(dup, str, len);
	return dup;
}
#define strN_dup0(str, len) _strN_dup0(str, len, __FILE__, __LINE__)
#define str0_dup0(str)       strN_dup0(str, strlen(str))


u32 strN_indexof(const char* haystack, u32 haystack_len, char needle)
{
	for(u32 i = 0; i < haystack_len; ++i)
		if(haystack[i] == needle)
			return i;
	return haystack_len;
}
#define str0_indexof(haystack, needle) strN_indexof(haystack, strlen(haystack), needle)


b32 strN_beginswith0(const_Str0 string, u32 string_len, const_Str0 prefix)
{
	int prefix_len = strlen(prefix);
	if(string_len < prefix_len)
		return 0;
	int cmpres = strncmp(string, prefix, prefix_len);
	return cmpres == 0;
}
#define str0_beginswith0(string, prefix) strN_beginswith0(string, strlen(string), prefix)


u32 strN_findlineN(char* string, u32 string_len, char** out_line, u32* out_line_len)
{
	if(string == NULL || string_len == 0)
		return 0;
	
	*out_line     = NULL;
	*out_line_len = 0;
	
	u32   line_len = string_len;
	char* line     = string;
	for(u32 i = 0; i < string_len; ++i)
	{
		if(string[i] == '\n')
		{
			line_len = i;
			break;
		}
	}
	
	// (line_len == string_len) -> no newlines in string -> advance by full length
	// (line_len <  string_len) -> newline found -> advance by line_len+1 (to skip newline)
	u32 advance_count = (line_len == string_len) ? string_len : line_len+1;
	
	// NOTE: Fuck you windows
	if(line_len > 0)
		if(line[line_len-1] == '\r')
			line_len -= 1;
	
	*out_line     = line;
	*out_line_len = line_len;
	return advance_count;
}


int _open_nointr(const_Str0 pathname, int flags, mode_t mode, const char* __file__, int __line__)
{
	int fd = -1;
	do {
		fd = open(pathname, flags, mode);
		if(fd == -1 && errno != EINTR)
			PRINT_ERROR_FL(__file__, __line__, "open(%s) failed", pathname);
	} while(fd == -1 && errno == EINTR);
	return fd;
}
#define open_nointr(pathname, flags, mode) _open_nointr(pathname, flags, mode, __FILE__, __LINE__)


int _openat_nointr(int dirfd, const_Str0 pathname, int flags, mode_t mode, const char* __file__, int __line__)
{
	int fd = -1;
	do {
		fd = openat(dirfd, pathname, flags, mode);
		if(fd == -1 && errno != EINTR)
			PRINT_ERROR_FL(__file__, __line__, "openat(%s) failed", pathname);
	} while(fd == -1 && errno == EINTR);
	return fd;
}
#define openat_nointr(dirfd, pathname, flags, mode) _openat_nointr(dirfd, pathname, flags, mode, __FILE__, __LINE__)


ssize_t write_nointr(int fd, const void* buf, size_t count)
{
	ssize_t total = 0;
	while(total < count)
	{
		ssize_t written = write(fd, buf + total, count - total);
		if(written == -1)
		{
			if(errno == EINTR)
				continue;
			else
				return -1;
		}
		else if(written == 0)
			return total;
		total += written;
	}
	return total;
}


ssize_t read_nointr(int fd, void* buf, size_t count)
{
	ssize_t total = 0;
	while(total < count)
	{
		ssize_t read_count = read(fd, buf + total, count - total);
		if(read_count == -1)
		{
			if(errno == EINTR)
				continue;
			else
				return -1;
		}
		else if(read_count == 0)
			return total;
		total += read_count;
	}
	return total;
}


int _flock_nointr(int fd, const char* __file__, int __line__)
{
	int error = 0;
	do {
		error = flock(fd, LOCK_SH);
		if(error && errno != EINTR)
			PRINT_ERROR_FL(__file__, __line__, "flock() failed");
	} while(error && errno == EINTR);
	return error;
}
#define flock_nointr(fd) _flock_nointr(fd, __FILE__, __LINE__)


int accept_nointr(int sockfd, struct sockaddr_in* sockaddr, socklen_t* addrlen, int flags)
{
	int socket = -1;
	do {
		socket = accept4(sockfd, (struct sockaddr*)sockaddr, addrlen, flags);
	} while(socket == -1 && errno == EINTR);
	return socket;
}


i32 create_resource_path(int docsdir_fd, Str0 resource_path, size_t resource_path_len)
{
	// NOTE: There SHOULD be no problems relative to PATH_MAX
	for(u32 i = 0; i < resource_path_len; ++i)
	{
		if(resource_path[i] != '/')
			continue;
		
		resource_path[i] = 0;
		int error = mkdirat(docsdir_fd, resource_path, 00755);
		resource_path[i] = '/';
		if(error && errno != EEXIST)
		{
			PRINT_ERROR("mkdir(%s) failed", resource_path);
			return RESULT_SERVER_ERROR;
		}
	}
	
	return RESULT_SUCCESS;
}


i32 read_entire_file(const_Str0 path, char** out_content, u32* out_content_size)
{
	// TODO: Configurable users path?
	struct stat statbuf = {};
	if(stat(path, &statbuf) != 0)
	{
		PRINT_ERROR("stat(%s) failed", path);
		return -1;
	}
	
	u32   buffer_size = statbuf.st_size;
	char* buffer      = memory_alloc(char, buffer_size);
	if(!buffer)
		return -1;
	
	int fd = open_nointr(path, O_RDONLY|O_CLOEXEC, 0);
	if(fd == -1)
	{
		memory_free(char, buffer, buffer_size);
		return -1;
	}
	
	ssize_t read_total = read_nointr(fd, buffer, buffer_size);
	close(fd);
	if(read_total != buffer_size)
	{
		PRINT_ERROR("read() failed");
		memory_free(char, buffer, buffer_size);
		return -1;
	}
	
	*out_content      = buffer;
	*out_content_size = buffer_size;
	return 0;
}


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


int inih_handler(void* user, const char* section, const char* option, const char* value)
{
	Configuration* config = user;
	if(strcmp(option, "listen_port_plain") == 0)
	{
		config->listen_port_plain = (u16)strtoul(value, NULL, 0);
	} else
	if(strcmp(option, "listen_port_crypt") == 0)
	{
		config->listen_port_crypt = (u16)strtoul(value, NULL, 0);
	} else
	if(strcmp(option, "extra_processes_count") == 0)
	{
		config->extra_processes_count = strtoul(value, NULL, 0);
	} else
	if(strcmp(option, "extra_threads_count") == 0)
	{
		config->extra_threads_count = strtoul(value, NULL, 0);
	} else
	if(strcmp(option, "disable_authorization") == 0)
	{
		config->disable_authorization = strtoul(value, NULL, 0) != 0;
	} else
	if(strcmp(option, "documents_root") == 0)
	{
		config->documents_root = str0_dup0(value);
	} else
	if(strcmp(option, "log_level") == 0)
	{
		config->log_level = strtoul(value, NULL, 0);
	}
	else return 0;
	
	return 1;
}


i32 parse_config_string(char* config_string, u32 config_string_len, Configuration* config)
{
	void* inih_user_data = config;
	Str0 config_string0 = strN_dup0(config_string, config_string_len);
	int error = ini_parse_string(config_string0, inih_handler, inih_user_data);
	str0_free(config_string0, config_string_len);
	if(error < 0)
	{
		PRINT_ERROR("ini_parse_string() failed");
		return -1;
	}
	else if(error > 0)
	{
		PRINT_ERROR("Configuration parse error at line %i", error);
		return -1;
	}
	return 0;
}


i32 parse_users_string(char*  users_string, u32  users_string_len,
                       Str0** out_users,    u32* out_users_count)
{
	u32   restore_len = users_string_len;
	char* restore     = users_string;
	
	u32 users_count = 0;
	while(users_string_len > 0)
	{
		u32   line_len = 0;
		char* line     = NULL;
		u32 advance_count = strN_findlineN(users_string, users_string_len, &line, &line_len);
		ASSERT(advance_count > 0);
		// if(advance_count == 0)
		// 	break;
		users_string     += advance_count;
		users_string_len -= advance_count;
		
		if(strN_indexof(line, line_len, ':') < line_len)
			++users_count;
	}
	
	if(users_count == 0)
	{
		*out_users       = NULL;
		*out_users_count = 0;
		return 0;
	}
	
	users_string     = restore;
	users_string_len = restore_len;
	
	Str0* users = memory_alloc(Str0, users_count);
	if(!users)
		return -1;
	
	u32 user_i = 0;
	while(user_i < users_count)
	{
		u32   line_len = 0;
		char* line     = NULL;
		u32 advance_count = strN_findlineN(users_string, users_string_len, &line, &line_len);
		ASSERT(advance_count > 0);
		// if(advance_count == 0)
		// 	break;
		users_string     += advance_count;
		users_string_len -= advance_count;
		
		if(strN_indexof(line, line_len, ':') == line_len)
			continue;
		
		users[user_i] = memory_alloc(char, line_len+1);
		if(!users[user_i])
		{
			for(u32 i = 0; i < user_i; ++i)
				str0_free(users[i], strlen(users[i]));
			memory_free(Str0, users, users_count);
			return -1;
		}
		memcpy(users[user_i], line, line_len);
		++user_i;
	}
	
	*out_users       = users;
	*out_users_count = users_count;
	
	return 0;
}


// typedef struct
// {
// 	pthread_mutex_t mutex;
// 	pthread_cond_t  cond;
// } monitor_t;

// int monitor_init(monitor_t* monitor)
// {
// 	int error = pthread_mutex_init(&monitor->mutex, NULL);
// 	if(!error)
// 		error = pthread_cond_init(&monitor->cond, NULL);
// 	return error;
// }

// int monitor_destroy(monitor_t* monitor)
// {
// 	int error = pthread_cond_destroy(&monitor->cond);
// 	if(!error)
// 		error = pthread_mutex_destroy(&monitor->mutex);
// 	return error;
// }

// void monitor_wait(monitor_t* monitor, b32* condition)
// {
// 	pthread_mutex_lock(&monitor->mutex);
// 	while(!(*condition))
// 		pthread_cond_wait(&monitor->cond, &monitor->mutex);
// 	pthread_mutex_unlock(&monitor->mutex);
// }

// void monitor_signal(monitor_t* monitor)
// {
// 	pthread_mutex_lock(&monitor->mutex);
// 	pthread_cond_signal(&monitor->cond);
// 	pthread_mutex_unlock(&monitor->mutex);
// }

struct State;

typedef void* ThreadTask(void*);

typedef struct
{
	struct State* state;
	int    socket;
	u32    address;
	u16    port;
} ThreadTaskArgs;

typedef struct ThreadJob
{
	ThreadTask*     task;
	ThreadTaskArgs* args;
	struct ThreadJob* next;
} ThreadJob;


typedef struct
{
	u32        threads_count;
	pthread_t* threads;
	
	b32 alive;
	pthread_mutex_t queue_mutex;
	pthread_cond_t  queue_cond;
	u32             queue_len;
	ThreadJob*      queue_head;
} ThreadPool;


static
void _thread_pool_job_destroy(ThreadJob* job)
{
	memory_free(ThreadJob, job, 1);
}


static
void* _thread_pool_main(void* param)
{
	ThreadPool* pool = param;
	while(1)
	{
		if(pthread_mutex_lock(&pool->queue_mutex) != 0)
		{
			PRINT_ERROR("pthread_mutex_lock() failed");
			return NULL;
		}
		
		while(pool->alive && !pool->queue_head)
		{
			if(pthread_cond_wait(&pool->queue_cond, &pool->queue_mutex) != 0)
			{
				PRINT_ERROR("pthread_mutex_lock() failed");
				pthread_mutex_unlock(&pool->queue_mutex);
				return NULL;
			}
		}
		
		if(!pool->alive)
			break;
		ASSERT(pool->queue_head);
		
		// Dequeue job
		ThreadJob* job = pool->queue_head;
		pool->queue_head = pool->queue_head->next;
		pool->queue_len -= 1;
		pthread_mutex_unlock(&pool->queue_mutex);
		
		job->task(job->args);
		_thread_pool_job_destroy(job);
	}
	
	pthread_mutex_unlock(&pool->queue_mutex);
	return NULL;
}


i32 thread_pool_start_job(ThreadPool* pool, ThreadTask* task, void* arg)
{
	if(!(pool->threads_count && pool->threads && task))
		return -1;
	if(pthread_mutex_lock(&pool->queue_mutex) != 0)
	{
		PRINT_ERROR("pthread_mutex_lock() failed");
		return -1;
	}
	
	ThreadJob* job = memory_alloc(ThreadJob, 1);
	if(!job)
	{	
		pthread_mutex_unlock(&pool->queue_mutex);
		return -1;
	}
	job->task = task;
	job->args = arg;
	job->next = NULL;
	
	if(!pool->queue_head)
	{
		pool->queue_head = job;
	}
	else
	{
		ThreadJob* tail = pool->queue_head;
		while(tail->next)
			tail = tail->next;
		tail->next = job;
	}
	pool->queue_len += 1;
	
	if(pthread_cond_signal(&pool->queue_cond) != 0)
	{
		PRINT_ERROR("pthread_cond_signal() failed");
		pthread_mutex_unlock(&pool->queue_mutex);
		return -1;
	}
	
	pthread_mutex_unlock(&pool->queue_mutex);
	return 0;
}


i32 _thread_pool_destroy(ThreadPool* pool, u32 join_count)
{
	pthread_mutex_lock(&pool->queue_mutex);
	pool->alive = 0;
	pthread_cond_broadcast(&pool->queue_cond);
	pthread_mutex_unlock(&pool->queue_mutex);
	
	for(u32 i = 0; i < join_count; ++i)
	{
		pthread_join(pool->threads[i], NULL);
	}
	
	while(pool->queue_head)
	{
		ThreadJob* head = pool->queue_head;
		pool->queue_head = head->next;
		_thread_pool_job_destroy(head);
		pool->queue_len -= 1;
	}
	
	memory_free(pthread_t, pool->threads, pool->threads_count);
	pool->threads       = NULL;
	pool->threads_count = 0;
	
	pthread_cond_destroy(&pool->queue_cond);
	pthread_mutex_destroy(&pool->queue_mutex);
	return 0;
}
#define thread_pool_destroy(pool) _thread_pool_destroy(pool, (pool)->threads_count)


i32 thread_pool_init(ThreadPool* pool, u32 threads_count)
{
	ASSERT(threads_count > 0);
	pool->threads_count = threads_count;
	pool->threads = memory_alloc(pthread_t, threads_count);
	if(!pool->threads)
		return -1;
	
	if(pthread_mutex_init(&pool->queue_mutex, NULL) != 0)
	{
		PRINT_ERROR("pthread_mutex_init() failed");
		memory_free(pthread_t, pool->threads, threads_count);
		return -1;
	}
	if(pthread_cond_init(&pool->queue_cond, NULL) != 0)
	{
		PRINT_ERROR("pthread_cond_init() failed");
		pthread_mutex_destroy(&pool->queue_mutex);
		memory_free(pthread_t, pool->threads, threads_count);
		return -1;
	}
	
	pool->alive = 1;
	pool->queue_len = 0;
	pool->queue_head = NULL;
	
	for(u32 i = 0; i < threads_count; ++i)
	{
		if(pthread_create(pool->threads+i, NULL, _thread_pool_main, pool) != 0)
		{
			PRINT_ERROR("pthread_create() failed");
			_thread_pool_destroy(pool, i);
			return -1;
		}
	}
	return 0;
}
