#include <assert.h>


const_Str0 _errno_as_string(int err)
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
#define errno_as_string _errno_as_string(errno)


int _open_nointr(const_Str0 pathname, int flags, mode_t mode, const char* __file__, int __line__)
{
	int fd;
	do {
		fd = open(pathname, flags, mode);
	} while(fd == -1 && errno == EINTR);
	return fd;
}
#define open_nointr(pathname, flags, mode) _open_nointr(pathname, flags, mode, __FILE__, __LINE__)


int _openat_nointr(int dirfd, const_Str0 pathname, int flags, mode_t mode, const char* __file__, int __line__)
{
	int fd;
	do {
		fd = openat(dirfd, pathname, flags, mode);
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


int _flock_nointr(int fd, int op, const char* __file__, int __line__)
{
	int error;
	do {
		error = flock(fd, op);
	} while(error && errno == EINTR);
	return error;
}
#define fshlock_nointr(fd) _flock_nointr(fd, LOCK_SH, __FILE__, __LINE__)
#define funlock_nointr(fd) _flock_nointr(fd, LOCK_UN, __FILE__, __LINE__)


int accept_nointr(int sockfd, struct sockaddr_in* sockaddr, socklen_t* addrlen, int flags)
{
	int socket = -1;
	do {
		socket = accept4(sockfd, (struct sockaddr*)sockaddr, addrlen, flags);
	} while(socket == -1 && errno == EINTR);
	return socket;
}


i32 read_entire_file(const_Str0 path, char** out_content, u32* out_content_size)
{
	// TODO: Configurable users path?
	struct stat statbuf = {};
	if(stat(path, &statbuf) != 0)
	{
		PRINT_ERROR("stat(%s) failed: errno = %s", path, errno_as_string);
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
		PRINT_ERROR("read(%s) failed: errno = %s", path, errno_as_string);
		memory_free(char, buffer, buffer_size);
		return -1;
	}
	
	*out_content      = buffer;
	*out_content_size = buffer_size;
	return 0;
}
