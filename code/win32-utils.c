#include <process.h> // _getpid()
#include <assert.h>
#include <stdlib.h>


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
		case ENOMSG          : return "ENOMSG";          //  42     /* No message of desired type */
		case EIDRM           : return "EIDRM";           //  43     /* Identifier removed */
		case ENOSTR          : return "ENOSTR";          //  60     /* Device not a stream */
		case ENODATA         : return "ENODATA";         //  61     /* No data available */
		case ETIME           : return "ETIME";           //  62     /* Timer expired */
		case ENOSR           : return "ENOSR";           //  63     /* Out of streams resources */
		case ENOLINK         : return "ENOLINK";         //  67     /* Link has been severed */
		case EPROTO          : return "EPROTO";          //  71     /* Protocol error */
		case EBADMSG         : return "EBADMSG";         //  74     /* Not a data message */
		case EOVERFLOW       : return "EOVERFLOW";       //  75     /* Value too large for defined data type */
		case EILSEQ          : return "EILSEQ";          //  84     /* Illegal byte sequence */
		case ENOTSOCK        : return "ENOTSOCK";        //  88     /* Socket operation on non-socket */
		case EDESTADDRREQ    : return "EDESTADDRREQ";    //  89     /* Destination address required */
		case EMSGSIZE        : return "EMSGSIZE";        //  90     /* Message too long */
		case EPROTOTYPE      : return "EPROTOTYPE";      //  91     /* Protocol wrong type for socket */
		case ENOPROTOOPT     : return "ENOPROTOOPT";     //  92     /* Protocol not available */
		case EPROTONOSUPPORT : return "EPROTONOSUPPORT"; //  93     /* Protocol not supported */
		case EOPNOTSUPP      : return "EOPNOTSUPP";      //  95     /* Operation not supported on transport endpoint */
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
		case ETIMEDOUT       : return "ETIMEDOUT";       // 110     /* Connection timed out */
		case ECONNREFUSED    : return "ECONNREFUSED";    // 111     /* Connection refused */
		case EHOSTUNREACH    : return "EHOSTUNREACH";    // 113     /* No route to host */
		case EALREADY        : return "EALREADY";        // 114     /* Operation already in progress */
		case EINPROGRESS     : return "EINPROGRESS";     // 115     /* Operation now in progress */
		case ECANCELED       : return "ECANCELED";       // 125     /* Operation Canceled */
		/* for robust mutexes */
		case EOWNERDEAD      : return "EOWNERDEAD";      // 130     /* Owner died */
		case ENOTRECOVERABLE : return "ENOTRECOVERABLE"; // 131     /* State not recoverable */
	} return "";
}
#define errno_as_string _errno_as_string(errno)


const_Str0 _le_as_string(int err)
{
	switch(err) {
	case ERROR_SUCCESS                                              : return "ERROR_SUCCESS";
	case ERROR_INVALID_FUNCTION                                     : return "ERROR_INVALID_FUNCTION";
	case ERROR_FILE_NOT_FOUND                                       : return "ERROR_FILE_NOT_FOUND";
	case ERROR_PATH_NOT_FOUND                                       : return "ERROR_PATH_NOT_FOUND";
	case ERROR_TOO_MANY_OPEN_FILES                                  : return "ERROR_TOO_MANY_OPEN_FILES";
	case ERROR_ACCESS_DENIED                                        : return "ERROR_ACCESS_DENIED";
	case ERROR_INVALID_HANDLE                                       : return "ERROR_INVALID_HANDLE";
	case ERROR_ARENA_TRASHED                                        : return "ERROR_ARENA_TRASHED";
	case ERROR_NOT_ENOUGH_MEMORY                                    : return "ERROR_NOT_ENOUGH_MEMORY";
	case ERROR_INVALID_BLOCK                                        : return "ERROR_INVALID_BLOCK";
	case ERROR_BAD_ENVIRONMENT                                      : return "ERROR_BAD_ENVIRONMENT";
	case ERROR_BAD_FORMAT                                           : return "ERROR_BAD_FORMAT";
	case ERROR_INVALID_ACCESS                                       : return "ERROR_INVALID_ACCESS";
	case ERROR_INVALID_DATA                                         : return "ERROR_INVALID_DATA";
	case ERROR_OUTOFMEMORY                                          : return "ERROR_OUTOFMEMORY";
	case ERROR_INVALID_DRIVE                                        : return "ERROR_INVALID_DRIVE";
	case ERROR_CURRENT_DIRECTORY                                    : return "ERROR_CURRENT_DIRECTORY";
	case ERROR_NOT_SAME_DEVICE                                      : return "ERROR_NOT_SAME_DEVICE";
	case ERROR_NO_MORE_FILES                                        : return "ERROR_NO_MORE_FILES";
	case ERROR_WRITE_PROTECT                                        : return "ERROR_WRITE_PROTECT";
	case ERROR_BAD_UNIT                                             : return "ERROR_BAD_UNIT";
	case ERROR_NOT_READY                                            : return "ERROR_NOT_READY";
	case ERROR_BAD_COMMAND                                          : return "ERROR_BAD_COMMAND";
	case ERROR_CRC                                                  : return "ERROR_CRC";
	case ERROR_BAD_LENGTH                                           : return "ERROR_BAD_LENGTH";
	case ERROR_SEEK                                                 : return "ERROR_SEEK";
	case ERROR_NOT_DOS_DISK                                         : return "ERROR_NOT_DOS_DISK";
	case ERROR_SECTOR_NOT_FOUND                                     : return "ERROR_SECTOR_NOT_FOUND";
	case ERROR_OUT_OF_PAPER                                         : return "ERROR_OUT_OF_PAPER";
	case ERROR_WRITE_FAULT                                          : return "ERROR_WRITE_FAULT";
	case ERROR_READ_FAULT                                           : return "ERROR_READ_FAULT";
	case ERROR_GEN_FAILURE                                          : return "ERROR_GEN_FAILURE";
	case ERROR_SHARING_VIOLATION                                    : return "ERROR_SHARING_VIOLATION";
	case ERROR_LOCK_VIOLATION                                       : return "ERROR_LOCK_VIOLATION";
	case ERROR_WRONG_DISK                                           : return "ERROR_WRONG_DISK";
	case ERROR_SHARING_BUFFER_EXCEEDED                              : return "ERROR_SHARING_BUFFER_EXCEEDED";
	case ERROR_HANDLE_EOF                                           : return "ERROR_HANDLE_EOF";
	case ERROR_HANDLE_DISK_FULL                                     : return "ERROR_HANDLE_DISK_FULL";
	case ERROR_NOT_SUPPORTED                                        : return "ERROR_NOT_SUPPORTED";
	case ERROR_REM_NOT_LIST                                         : return "ERROR_REM_NOT_LIST";
	case ERROR_DUP_NAME                                             : return "ERROR_DUP_NAME";
	case ERROR_BAD_NETPATH                                          : return "ERROR_BAD_NETPATH";
	case ERROR_NETWORK_BUSY                                         : return "ERROR_NETWORK_BUSY";
	case ERROR_DEV_NOT_EXIST                                        : return "ERROR_DEV_NOT_EXIST";
	case ERROR_TOO_MANY_CMDS                                        : return "ERROR_TOO_MANY_CMDS";
	case ERROR_ADAP_HDW_ERR                                         : return "ERROR_ADAP_HDW_ERR";
	case ERROR_BAD_NET_RESP                                         : return "ERROR_BAD_NET_RESP";
	case ERROR_UNEXP_NET_ERR                                        : return "ERROR_UNEXP_NET_ERR";
	case ERROR_BAD_REM_ADAP                                         : return "ERROR_BAD_REM_ADAP";
	case ERROR_PRINTQ_FULL                                          : return "ERROR_PRINTQ_FULL";
	case ERROR_NO_SPOOL_SPACE                                       : return "ERROR_NO_SPOOL_SPACE";
	case ERROR_PRINT_CANCELLED                                      : return "ERROR_PRINT_CANCELLED";
	case ERROR_NETNAME_DELETED                                      : return "ERROR_NETNAME_DELETED";
	case ERROR_NETWORK_ACCESS_DENIED                                : return "ERROR_NETWORK_ACCESS_DENIED";
	case ERROR_BAD_DEV_TYPE                                         : return "ERROR_BAD_DEV_TYPE";
	case ERROR_BAD_NET_NAME                                         : return "ERROR_BAD_NET_NAME";
	case ERROR_TOO_MANY_NAMES                                       : return "ERROR_TOO_MANY_NAMES";
	case ERROR_TOO_MANY_SESS                                        : return "ERROR_TOO_MANY_SESS";
	case ERROR_SHARING_PAUSED                                       : return "ERROR_SHARING_PAUSED";
	case ERROR_REQ_NOT_ACCEP                                        : return "ERROR_REQ_NOT_ACCEP";
	case ERROR_REDIR_PAUSED                                         : return "ERROR_REDIR_PAUSED";
	case ERROR_FILE_EXISTS                                          : return "ERROR_FILE_EXISTS";
	case ERROR_CANNOT_MAKE                                          : return "ERROR_CANNOT_MAKE";
	case ERROR_FAIL_I24                                             : return "ERROR_FAIL_I24";
	case ERROR_OUT_OF_STRUCTURES                                    : return "ERROR_OUT_OF_STRUCTURES";
	case ERROR_ALREADY_ASSIGNED                                     : return "ERROR_ALREADY_ASSIGNED";
	case ERROR_INVALID_PASSWORD                                     : return "ERROR_INVALID_PASSWORD";
	case ERROR_INVALID_PARAMETER                                    : return "ERROR_INVALID_PARAMETER";
	case ERROR_NET_WRITE_FAULT                                      : return "ERROR_NET_WRITE_FAULT";
	case ERROR_NO_PROC_SLOTS                                        : return "ERROR_NO_PROC_SLOTS";
	case ERROR_TOO_MANY_SEMAPHORES                                  : return "ERROR_TOO_MANY_SEMAPHORES";
	case ERROR_EXCL_SEM_ALREADY_OWNED                               : return "ERROR_EXCL_SEM_ALREADY_OWNED";
	case ERROR_SEM_IS_SET                                           : return "ERROR_SEM_IS_SET";
	case ERROR_TOO_MANY_SEM_REQUESTS                                : return "ERROR_TOO_MANY_SEM_REQUESTS";
	case ERROR_INVALID_AT_INTERRUPT_TIME                            : return "ERROR_INVALID_AT_INTERRUPT_TIME";
	case ERROR_SEM_OWNER_DIED                                       : return "ERROR_SEM_OWNER_DIED";
	case ERROR_SEM_USER_LIMIT                                       : return "ERROR_SEM_USER_LIMIT";
	case ERROR_DISK_CHANGE                                          : return "ERROR_DISK_CHANGE";
	case ERROR_DRIVE_LOCKED                                         : return "ERROR_DRIVE_LOCKED";
	case ERROR_BROKEN_PIPE                                          : return "ERROR_BROKEN_PIPE";
	case ERROR_OPEN_FAILED                                          : return "ERROR_OPEN_FAILED";
	case ERROR_BUFFER_OVERFLOW                                      : return "ERROR_BUFFER_OVERFLOW";
	case ERROR_DISK_FULL                                            : return "ERROR_DISK_FULL";
	case ERROR_NO_MORE_SEARCH_HANDLES                               : return "ERROR_NO_MORE_SEARCH_HANDLES";
	case ERROR_INVALID_TARGET_HANDLE                                : return "ERROR_INVALID_TARGET_HANDLE";
	case ERROR_INVALID_CATEGORY                                     : return "ERROR_INVALID_CATEGORY";
	case ERROR_INVALID_VERIFY_SWITCH                                : return "ERROR_INVALID_VERIFY_SWITCH";
	case ERROR_BAD_DRIVER_LEVEL                                     : return "ERROR_BAD_DRIVER_LEVEL";
	case ERROR_CALL_NOT_IMPLEMENTED                                 : return "ERROR_CALL_NOT_IMPLEMENTED";
	case ERROR_SEM_TIMEOUT                                          : return "ERROR_SEM_TIMEOUT";
	case ERROR_INSUFFICIENT_BUFFER                                  : return "ERROR_INSUFFICIENT_BUFFER";
	case ERROR_INVALID_NAME                                         : return "ERROR_INVALID_NAME";
	case ERROR_INVALID_LEVEL                                        : return "ERROR_INVALID_LEVEL";
	case ERROR_NO_VOLUME_LABEL                                      : return "ERROR_NO_VOLUME_LABEL";
	case ERROR_MOD_NOT_FOUND                                        : return "ERROR_MOD_NOT_FOUND";
	case ERROR_PROC_NOT_FOUND                                       : return "ERROR_PROC_NOT_FOUND";
	case ERROR_WAIT_NO_CHILDREN                                     : return "ERROR_WAIT_NO_CHILDREN";
	case ERROR_CHILD_NOT_COMPLETE                                   : return "ERROR_CHILD_NOT_COMPLETE";
	case ERROR_DIRECT_ACCESS_HANDLE                                 : return "ERROR_DIRECT_ACCESS_HANDLE";
	case ERROR_NEGATIVE_SEEK                                        : return "ERROR_NEGATIVE_SEEK";
	case ERROR_SEEK_ON_DEVICE                                       : return "ERROR_SEEK_ON_DEVICE";
	case ERROR_IS_JOIN_TARGET                                       : return "ERROR_IS_JOIN_TARGET";
	case ERROR_IS_JOINED                                            : return "ERROR_IS_JOINED";
	case ERROR_IS_SUBSTED                                           : return "ERROR_IS_SUBSTED";
	case ERROR_NOT_JOINED                                           : return "ERROR_NOT_JOINED";
	case ERROR_NOT_SUBSTED                                          : return "ERROR_NOT_SUBSTED";
	case ERROR_JOIN_TO_JOIN                                         : return "ERROR_JOIN_TO_JOIN";
	case ERROR_SUBST_TO_SUBST                                       : return "ERROR_SUBST_TO_SUBST";
	case ERROR_JOIN_TO_SUBST                                        : return "ERROR_JOIN_TO_SUBST";
	case ERROR_SUBST_TO_JOIN                                        : return "ERROR_SUBST_TO_JOIN";
	case ERROR_BUSY_DRIVE                                           : return "ERROR_BUSY_DRIVE";
	case ERROR_SAME_DRIVE                                           : return "ERROR_SAME_DRIVE";
	case ERROR_DIR_NOT_ROOT                                         : return "ERROR_DIR_NOT_ROOT";
	case ERROR_DIR_NOT_EMPTY                                        : return "ERROR_DIR_NOT_EMPTY";
	case ERROR_IS_SUBST_PATH                                        : return "ERROR_IS_SUBST_PATH";
	case ERROR_IS_JOIN_PATH                                         : return "ERROR_IS_JOIN_PATH";
	case ERROR_PATH_BUSY                                            : return "ERROR_PATH_BUSY";
	case ERROR_IS_SUBST_TARGET                                      : return "ERROR_IS_SUBST_TARGET";
	case ERROR_SYSTEM_TRACE                                         : return "ERROR_SYSTEM_TRACE";
	case ERROR_INVALID_EVENT_COUNT                                  : return "ERROR_INVALID_EVENT_COUNT";
	case ERROR_TOO_MANY_MUXWAITERS                                  : return "ERROR_TOO_MANY_MUXWAITERS";
	case ERROR_INVALID_LIST_FORMAT                                  : return "ERROR_INVALID_LIST_FORMAT";
	case ERROR_LABEL_TOO_LONG                                       : return "ERROR_LABEL_TOO_LONG";
	case ERROR_TOO_MANY_TCBS                                        : return "ERROR_TOO_MANY_TCBS";
	case ERROR_SIGNAL_REFUSED                                       : return "ERROR_SIGNAL_REFUSED";
	case ERROR_DISCARDED                                            : return "ERROR_DISCARDED";
	case ERROR_NOT_LOCKED                                           : return "ERROR_NOT_LOCKED";
	case ERROR_BAD_THREADID_ADDR                                    : return "ERROR_BAD_THREADID_ADDR";
	case ERROR_BAD_ARGUMENTS                                        : return "ERROR_BAD_ARGUMENTS";
	case ERROR_BAD_PATHNAME                                         : return "ERROR_BAD_PATHNAME";
	case ERROR_SIGNAL_PENDING                                       : return "ERROR_SIGNAL_PENDING";
	case ERROR_MAX_THRDS_REACHED                                    : return "ERROR_MAX_THRDS_REACHED";
	case ERROR_LOCK_FAILED                                          : return "ERROR_LOCK_FAILED";
	case ERROR_BUSY                                                 : return "ERROR_BUSY";
	case ERROR_DEVICE_SUPPORT_IN_PROGRESS                           : return "ERROR_DEVICE_SUPPORT_IN_PROGRESS";
	case ERROR_CANCEL_VIOLATION                                     : return "ERROR_CANCEL_VIOLATION";
	case ERROR_ATOMIC_LOCKS_NOT_SUPPORTED                           : return "ERROR_ATOMIC_LOCKS_NOT_SUPPORTED";
	case ERROR_INVALID_SEGMENT_NUMBER                               : return "ERROR_INVALID_SEGMENT_NUMBER";
	case ERROR_INVALID_ORDINAL                                      : return "ERROR_INVALID_ORDINAL";
	case ERROR_ALREADY_EXISTS                                       : return "ERROR_ALREADY_EXISTS";
	case ERROR_INVALID_FLAG_NUMBER                                  : return "ERROR_INVALID_FLAG_NUMBER";
	case ERROR_SEM_NOT_FOUND                                        : return "ERROR_SEM_NOT_FOUND";
	case ERROR_INVALID_STARTING_CODESEG                             : return "ERROR_INVALID_STARTING_CODESEG";
	case ERROR_INVALID_STACKSEG                                     : return "ERROR_INVALID_STACKSEG";
	case ERROR_INVALID_MODULETYPE                                   : return "ERROR_INVALID_MODULETYPE";
	case ERROR_INVALID_EXE_SIGNATURE                                : return "ERROR_INVALID_EXE_SIGNATURE";
	case ERROR_EXE_MARKED_INVALID                                   : return "ERROR_EXE_MARKED_INVALID";
	case ERROR_BAD_EXE_FORMAT                                       : return "ERROR_BAD_EXE_FORMAT";
	case ERROR_ITERATED_DATA_EXCEEDS_64k                            : return "ERROR_ITERATED_DATA_EXCEEDS_64k";
	case ERROR_INVALID_MINALLOCSIZE                                 : return "ERROR_INVALID_MINALLOCSIZE";
	case ERROR_DYNLINK_FROM_INVALID_RING                            : return "ERROR_DYNLINK_FROM_INVALID_RING";
	case ERROR_IOPL_NOT_ENABLED                                     : return "ERROR_IOPL_NOT_ENABLED";
	case ERROR_INVALID_SEGDPL                                       : return "ERROR_INVALID_SEGDPL";
	case ERROR_AUTODATASEG_EXCEEDS_64k                              : return "ERROR_AUTODATASEG_EXCEEDS_64k";
	case ERROR_RING2SEG_MUST_BE_MOVABLE                             : return "ERROR_RING2SEG_MUST_BE_MOVABLE";
	case ERROR_RELOC_CHAIN_XEEDS_SEGLIM                             : return "ERROR_RELOC_CHAIN_XEEDS_SEGLIM";
	case ERROR_INFLOOP_IN_RELOC_CHAIN                               : return "ERROR_INFLOOP_IN_RELOC_CHAIN";
	case ERROR_ENVVAR_NOT_FOUND                                     : return "ERROR_ENVVAR_NOT_FOUND";
	case ERROR_NO_SIGNAL_SENT                                       : return "ERROR_NO_SIGNAL_SENT";
	case ERROR_FILENAME_EXCED_RANGE                                 : return "ERROR_FILENAME_EXCED_RANGE";
	case ERROR_RING2_STACK_IN_USE                                   : return "ERROR_RING2_STACK_IN_USE";
	case ERROR_META_EXPANSION_TOO_LONG                              : return "ERROR_META_EXPANSION_TOO_LONG";
	case ERROR_INVALID_SIGNAL_NUMBER                                : return "ERROR_INVALID_SIGNAL_NUMBER";
	case ERROR_THREAD_1_INACTIVE                                    : return "ERROR_THREAD_1_INACTIVE";
	case ERROR_LOCKED                                               : return "ERROR_LOCKED";
	case ERROR_TOO_MANY_MODULES                                     : return "ERROR_TOO_MANY_MODULES";
	case ERROR_NESTING_NOT_ALLOWED                                  : return "ERROR_NESTING_NOT_ALLOWED";
	case ERROR_EXE_MACHINE_TYPE_MISMATCH                            : return "ERROR_EXE_MACHINE_TYPE_MISMATCH";
	case ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY                      : return "ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY";
	case ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY               : return "ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY";
	case ERROR_FILE_CHECKED_OUT                                     : return "ERROR_FILE_CHECKED_OUT";
	case ERROR_CHECKOUT_REQUIRED                                    : return "ERROR_CHECKOUT_REQUIRED";
	case ERROR_BAD_FILE_TYPE                                        : return "ERROR_BAD_FILE_TYPE";
	case ERROR_FILE_TOO_LARGE                                       : return "ERROR_FILE_TOO_LARGE";
	case ERROR_FORMS_AUTH_REQUIRED                                  : return "ERROR_FORMS_AUTH_REQUIRED";
	case ERROR_VIRUS_INFECTED                                       : return "ERROR_VIRUS_INFECTED";
	case ERROR_VIRUS_DELETED                                        : return "ERROR_VIRUS_DELETED";
	case ERROR_PIPE_LOCAL                                           : return "ERROR_PIPE_LOCAL";
	case ERROR_BAD_PIPE                                             : return "ERROR_BAD_PIPE";
	case ERROR_PIPE_BUSY                                            : return "ERROR_PIPE_BUSY";
	case ERROR_NO_DATA                                              : return "ERROR_NO_DATA";
	case ERROR_PIPE_NOT_CONNECTED                                   : return "ERROR_PIPE_NOT_CONNECTED";
	case ERROR_MORE_DATA                                            : return "ERROR_MORE_DATA";
	case ERROR_NO_WORK_DONE                                         : return "ERROR_NO_WORK_DONE";
	case ERROR_VC_DISCONNECTED                                      : return "ERROR_VC_DISCONNECTED";
	case ERROR_INVALID_EA_NAME                                      : return "ERROR_INVALID_EA_NAME";
	case ERROR_EA_LIST_INCONSISTENT                                 : return "ERROR_EA_LIST_INCONSISTENT";
	case WAIT_TIMEOUT                                               : return "WAIT_TIMEOUT";
	case ERROR_NO_MORE_ITEMS                                        : return "ERROR_NO_MORE_ITEMS";
	case ERROR_CANNOT_COPY                                          : return "ERROR_CANNOT_COPY";
	case ERROR_DIRECTORY                                            : return "ERROR_DIRECTORY";
	case ERROR_EAS_DIDNT_FIT                                        : return "ERROR_EAS_DIDNT_FIT";
	case ERROR_EA_FILE_CORRUPT                                      : return "ERROR_EA_FILE_CORRUPT";
	case ERROR_EA_TABLE_FULL                                        : return "ERROR_EA_TABLE_FULL";
	case ERROR_INVALID_EA_HANDLE                                    : return "ERROR_INVALID_EA_HANDLE";
	case ERROR_EAS_NOT_SUPPORTED                                    : return "ERROR_EAS_NOT_SUPPORTED";
	case ERROR_NOT_OWNER                                            : return "ERROR_NOT_OWNER";
	case ERROR_TOO_MANY_POSTS                                       : return "ERROR_TOO_MANY_POSTS";
	case ERROR_PARTIAL_COPY                                         : return "ERROR_PARTIAL_COPY";
	case ERROR_OPLOCK_NOT_GRANTED                                   : return "ERROR_OPLOCK_NOT_GRANTED";
	case ERROR_INVALID_OPLOCK_PROTOCOL                              : return "ERROR_INVALID_OPLOCK_PROTOCOL";
	case ERROR_DISK_TOO_FRAGMENTED                                  : return "ERROR_DISK_TOO_FRAGMENTED";
	case ERROR_DELETE_PENDING                                       : return "ERROR_DELETE_PENDING";
	case ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING : return "ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING";
	case ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME                    : return "ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME";
	case ERROR_SECURITY_STREAM_IS_INCONSISTENT                      : return "ERROR_SECURITY_STREAM_IS_INCONSISTENT";
	case ERROR_INVALID_LOCK_RANGE                                   : return "ERROR_INVALID_LOCK_RANGE";
	case ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT                          : return "ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT";
	case ERROR_NOTIFICATION_GUID_ALREADY_DEFINED                    : return "ERROR_NOTIFICATION_GUID_ALREADY_DEFINED";
	case ERROR_INVALID_EXCEPTION_HANDLER                            : return "ERROR_INVALID_EXCEPTION_HANDLER";
	case ERROR_DUPLICATE_PRIVILEGES                                 : return "ERROR_DUPLICATE_PRIVILEGES";
	case ERROR_NO_RANGES_PROCESSED                                  : return "ERROR_NO_RANGES_PROCESSED";
	case ERROR_NOT_ALLOWED_ON_SYSTEM_FILE                           : return "ERROR_NOT_ALLOWED_ON_SYSTEM_FILE";
	case ERROR_DISK_RESOURCES_EXHAUSTED                             : return "ERROR_DISK_RESOURCES_EXHAUSTED";
	case ERROR_INVALID_TOKEN                                        : return "ERROR_INVALID_TOKEN";
	case ERROR_DEVICE_FEATURE_NOT_SUPPORTED                         : return "ERROR_DEVICE_FEATURE_NOT_SUPPORTED";
	case ERROR_MR_MID_NOT_FOUND                                     : return "ERROR_MR_MID_NOT_FOUND";
	case ERROR_SCOPE_NOT_FOUND                                      : return "ERROR_SCOPE_NOT_FOUND";
	case ERROR_UNDEFINED_SCOPE                                      : return "ERROR_UNDEFINED_SCOPE";
	case ERROR_INVALID_CAP                                          : return "ERROR_INVALID_CAP";
	case ERROR_DEVICE_UNREACHABLE                                   : return "ERROR_DEVICE_UNREACHABLE";
	case ERROR_DEVICE_NO_RESOURCES                                  : return "ERROR_DEVICE_NO_RESOURCES";
	case ERROR_DATA_CHECKSUM_ERROR                                  : return "ERROR_DATA_CHECKSUM_ERROR";
	case ERROR_INTERMIXED_KERNEL_EA_OPERATION                       : return "ERROR_INTERMIXED_KERNEL_EA_OPERATION";
	case ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED                        : return "ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED";
	case ERROR_OFFSET_ALIGNMENT_VIOLATION                           : return "ERROR_OFFSET_ALIGNMENT_VIOLATION";
	case ERROR_INVALID_FIELD_IN_PARAMETER_LIST                      : return "ERROR_INVALID_FIELD_IN_PARAMETER_LIST";
	case ERROR_OPERATION_IN_PROGRESS                                : return "ERROR_OPERATION_IN_PROGRESS";
	case ERROR_BAD_DEVICE_PATH                                      : return "ERROR_BAD_DEVICE_PATH";
	case ERROR_TOO_MANY_DESCRIPTORS                                 : return "ERROR_TOO_MANY_DESCRIPTORS";
	case ERROR_SCRUB_DATA_DISABLED                                  : return "ERROR_SCRUB_DATA_DISABLED";
	case ERROR_NOT_REDUNDANT_STORAGE                                : return "ERROR_NOT_REDUNDANT_STORAGE";
	case ERROR_RESIDENT_FILE_NOT_SUPPORTED                          : return "ERROR_RESIDENT_FILE_NOT_SUPPORTED";
	case ERROR_COMPRESSED_FILE_NOT_SUPPORTED                        : return "ERROR_COMPRESSED_FILE_NOT_SUPPORTED";
	case ERROR_DIRECTORY_NOT_SUPPORTED                              : return "ERROR_DIRECTORY_NOT_SUPPORTED";
	case ERROR_NOT_READ_FROM_COPY                                   : return "ERROR_NOT_READ_FROM_COPY";
	case ERROR_FT_WRITE_FAILURE                                     : return "ERROR_FT_WRITE_FAILURE";
	case ERROR_FT_DI_SCAN_REQUIRED                                  : return "ERROR_FT_DI_SCAN_REQUIRED";
	case ERROR_INVALID_KERNEL_INFO_VERSION                          : return "ERROR_INVALID_KERNEL_INFO_VERSION";
	case ERROR_INVALID_PEP_INFO_VERSION                             : return "ERROR_INVALID_PEP_INFO_VERSION";
	case ERROR_OBJECT_NOT_EXTERNALLY_BACKED                         : return "ERROR_OBJECT_NOT_EXTERNALLY_BACKED";
	case ERROR_EXTERNAL_BACKING_PROVIDER_UNKNOWN                    : return "ERROR_EXTERNAL_BACKING_PROVIDER_UNKNOWN";
	case ERROR_COMPRESSION_NOT_BENEFICIAL                           : return "ERROR_COMPRESSION_NOT_BENEFICIAL";
	case ERROR_STORAGE_TOPOLOGY_ID_MISMATCH                         : return "ERROR_STORAGE_TOPOLOGY_ID_MISMATCH";
	case ERROR_BLOCKED_BY_PARENTAL_CONTROLS                         : return "ERROR_BLOCKED_BY_PARENTAL_CONTROLS";
	case ERROR_BLOCK_TOO_MANY_REFERENCES                            : return "ERROR_BLOCK_TOO_MANY_REFERENCES";
	case ERROR_MARKED_TO_DISALLOW_WRITES                            : return "ERROR_MARKED_TO_DISALLOW_WRITES";
	case ERROR_ENCLAVE_FAILURE                                      : return "ERROR_ENCLAVE_FAILURE";
	case ERROR_FAIL_NOACTION_REBOOT                                 : return "ERROR_FAIL_NOACTION_REBOOT";
	case ERROR_FAIL_SHUTDOWN                                        : return "ERROR_FAIL_SHUTDOWN";
	case ERROR_FAIL_RESTART                                         : return "ERROR_FAIL_RESTART";
	case ERROR_MAX_SESSIONS_REACHED                                 : return "ERROR_MAX_SESSIONS_REACHED";
	case ERROR_NETWORK_ACCESS_DENIED_EDP                            : return "ERROR_NETWORK_ACCESS_DENIED_EDP";
	case ERROR_DEVICE_HINT_NAME_BUFFER_TOO_SMALL                    : return "ERROR_DEVICE_HINT_NAME_BUFFER_TOO_SMALL";
	case ERROR_EDP_POLICY_DENIES_OPERATION                          : return "ERROR_EDP_POLICY_DENIES_OPERATION";
	case ERROR_EDP_DPL_POLICY_CANT_BE_SATISFIED                     : return "ERROR_EDP_DPL_POLICY_CANT_BE_SATISFIED";
	case ERROR_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT                : return "ERROR_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT";
	case ERROR_DEVICE_IN_MAINTENANCE                                : return "ERROR_DEVICE_IN_MAINTENANCE";
	case ERROR_NOT_SUPPORTED_ON_DAX                                 : return "ERROR_NOT_SUPPORTED_ON_DAX";
	case ERROR_DAX_MAPPING_EXISTS                                   : return "ERROR_DAX_MAPPING_EXISTS";
	case ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING                      : return "ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING";
	case ERROR_CLOUD_FILE_METADATA_CORRUPT                          : return "ERROR_CLOUD_FILE_METADATA_CORRUPT";
	case ERROR_CLOUD_FILE_METADATA_TOO_LARGE                        : return "ERROR_CLOUD_FILE_METADATA_TOO_LARGE";
	case ERROR_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE                   : return "ERROR_CLOUD_FILE_PROPERTY_BLOB_TOO_LARGE";
	case ERROR_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH           : return "ERROR_CLOUD_FILE_PROPERTY_BLOB_CHECKSUM_MISMATCH";
	case ERROR_CHILD_PROCESS_BLOCKED                                : return "ERROR_CHILD_PROCESS_BLOCKED";
	case ERROR_STORAGE_LOST_DATA_PERSISTENCE                        : return "ERROR_STORAGE_LOST_DATA_PERSISTENCE";
	case ERROR_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE               : return "ERROR_FILE_SYSTEM_VIRTUALIZATION_UNAVAILABLE";
	case ERROR_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT          : return "ERROR_FILE_SYSTEM_VIRTUALIZATION_METADATA_CORRUPT";
	case ERROR_FILE_SYSTEM_VIRTUALIZATION_BUSY                      : return "ERROR_FILE_SYSTEM_VIRTUALIZATION_BUSY";
	case ERROR_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN          : return "ERROR_FILE_SYSTEM_VIRTUALIZATION_PROVIDER_UNKNOWN";
	case ERROR_GDI_HANDLE_LEAK                                      : return "ERROR_GDI_HANDLE_LEAK";
	case ERROR_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS                   : return "ERROR_CLOUD_FILE_TOO_MANY_PROPERTY_BLOBS";
	case ERROR_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED            : return "ERROR_CLOUD_FILE_PROPERTY_VERSION_NOT_SUPPORTED";
	case ERROR_NOT_A_CLOUD_FILE                                     : return "ERROR_NOT_A_CLOUD_FILE";
	case ERROR_CLOUD_FILE_NOT_IN_SYNC                               : return "ERROR_CLOUD_FILE_NOT_IN_SYNC";
	case ERROR_CLOUD_FILE_ALREADY_CONNECTED                         : return "ERROR_CLOUD_FILE_ALREADY_CONNECTED";
	case ERROR_CLOUD_FILE_NOT_SUPPORTED                             : return "ERROR_CLOUD_FILE_NOT_SUPPORTED";
	case ERROR_CLOUD_FILE_INVALID_REQUEST                           : return "ERROR_CLOUD_FILE_INVALID_REQUEST";
	case ERROR_CLOUD_FILE_READ_ONLY_VOLUME                          : return "ERROR_CLOUD_FILE_READ_ONLY_VOLUME";
	case ERROR_CLOUD_FILE_CONNECTED_PROVIDER_ONLY                   : return "ERROR_CLOUD_FILE_CONNECTED_PROVIDER_ONLY";
	case ERROR_CLOUD_FILE_VALIDATION_FAILED                         : return "ERROR_CLOUD_FILE_VALIDATION_FAILED";
	case ERROR_SMB1_NOT_AVAILABLE                                   : return "ERROR_SMB1_NOT_AVAILABLE";
	case ERROR_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION         : return "ERROR_FILE_SYSTEM_VIRTUALIZATION_INVALID_OPERATION";
	case ERROR_CLOUD_FILE_AUTHENTICATION_FAILED                     : return "ERROR_CLOUD_FILE_AUTHENTICATION_FAILED";
	case ERROR_CLOUD_FILE_INSUFFICIENT_RESOURCES                    : return "ERROR_CLOUD_FILE_INSUFFICIENT_RESOURCES";
	case ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE                       : return "ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE";
	case ERROR_CLOUD_FILE_UNSUCCESSFUL                              : return "ERROR_CLOUD_FILE_UNSUCCESSFUL";
	case ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT                       : return "ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT";
	case ERROR_CLOUD_FILE_IN_USE                                    : return "ERROR_CLOUD_FILE_IN_USE";
	case ERROR_CLOUD_FILE_PINNED                                    : return "ERROR_CLOUD_FILE_PINNED";
	case ERROR_CLOUD_FILE_REQUEST_ABORTED                           : return "ERROR_CLOUD_FILE_REQUEST_ABORTED";
	case ERROR_CLOUD_FILE_PROPERTY_CORRUPT                          : return "ERROR_CLOUD_FILE_PROPERTY_CORRUPT";
	case ERROR_CLOUD_FILE_ACCESS_DENIED                             : return "ERROR_CLOUD_FILE_ACCESS_DENIED";
	case ERROR_CLOUD_FILE_INCOMPATIBLE_HARDLINKS                    : return "ERROR_CLOUD_FILE_INCOMPATIBLE_HARDLINKS";
	case ERROR_CLOUD_FILE_PROPERTY_LOCK_CONFLICT                    : return "ERROR_CLOUD_FILE_PROPERTY_LOCK_CONFLICT";
	case ERROR_CLOUD_FILE_REQUEST_CANCELED                          : return "ERROR_CLOUD_FILE_REQUEST_CANCELED";
	case ERROR_EXTERNAL_SYSKEY_NOT_SUPPORTED                        : return "ERROR_EXTERNAL_SYSKEY_NOT_SUPPORTED";
	case ERROR_THREAD_MODE_ALREADY_BACKGROUND                       : return "ERROR_THREAD_MODE_ALREADY_BACKGROUND";
	case ERROR_THREAD_MODE_NOT_BACKGROUND                           : return "ERROR_THREAD_MODE_NOT_BACKGROUND";
	case ERROR_PROCESS_MODE_ALREADY_BACKGROUND                      : return "ERROR_PROCESS_MODE_ALREADY_BACKGROUND";
	case ERROR_PROCESS_MODE_NOT_BACKGROUND                          : return "ERROR_PROCESS_MODE_NOT_BACKGROUND";
	} return "";
}
#define LastErrorAsString _le_as_string(GetLastError())


const_Str0 _wsale_as_string(int err)
{
	switch(err) {
	case WSAEINTR                    : return "WSAEINTR";
	case WSAEBADF                    : return "WSAEBADF";
	case WSAEACCES                   : return "WSAEACCES";
	case WSAEFAULT                   : return "WSAEFAULT";
	case WSAEINVAL                   : return "WSAEINVAL";
	case WSAEMFILE                   : return "WSAEMFILE";
	case WSAEWOULDBLOCK              : return "WSAEWOULDBLOCK";
	case WSAEINPROGRESS              : return "WSAEINPROGRESS";
	case WSAEALREADY                 : return "WSAEALREADY";
	case WSAENOTSOCK                 : return "WSAENOTSOCK";
	case WSAEDESTADDRREQ             : return "WSAEDESTADDRREQ";
	case WSAEMSGSIZE                 : return "WSAEMSGSIZE";
	case WSAEPROTOTYPE               : return "WSAEPROTOTYPE";
	case WSAENOPROTOOPT              : return "WSAENOPROTOOPT";
	case WSAEPROTONOSUPPORT          : return "WSAEPROTONOSUPPORT";
	case WSAESOCKTNOSUPPORT          : return "WSAESOCKTNOSUPPORT";
	case WSAEOPNOTSUPP               : return "WSAEOPNOTSUPP";
	case WSAEPFNOSUPPORT             : return "WSAEPFNOSUPPORT";
	case WSAEAFNOSUPPORT             : return "WSAEAFNOSUPPORT";
	case WSAEADDRINUSE               : return "WSAEADDRINUSE";
	case WSAEADDRNOTAVAIL            : return "WSAEADDRNOTAVAIL";
	case WSAENETDOWN                 : return "WSAENETDOWN";
	case WSAENETUNREACH              : return "WSAENETUNREACH";
	case WSAENETRESET                : return "WSAENETRESET";
	case WSAECONNABORTED             : return "WSAECONNABORTED";
	case WSAECONNRESET               : return "WSAECONNRESET";
	case WSAENOBUFS                  : return "WSAENOBUFS";
	case WSAEISCONN                  : return "WSAEISCONN";
	case WSAENOTCONN                 : return "WSAENOTCONN";
	case WSAESHUTDOWN                : return "WSAESHUTDOWN";
	case WSAETOOMANYREFS             : return "WSAETOOMANYREFS";
	case WSAETIMEDOUT                : return "WSAETIMEDOUT";
	case WSAECONNREFUSED             : return "WSAECONNREFUSED";
	case WSAELOOP                    : return "WSAELOOP";
	case WSAENAMETOOLONG             : return "WSAENAMETOOLONG";
	case WSAEHOSTDOWN                : return "WSAEHOSTDOWN";
	case WSAEHOSTUNREACH             : return "WSAEHOSTUNREACH";
	case WSAENOTEMPTY                : return "WSAENOTEMPTY";
	case WSAEPROCLIM                 : return "WSAEPROCLIM";
	case WSAEUSERS                   : return "WSAEUSERS";
	case WSAEDQUOT                   : return "WSAEDQUOT";
	case WSAESTALE                   : return "WSAESTALE";
	case WSAEREMOTE                  : return "WSAEREMOTE";
	case WSASYSNOTREADY              : return "WSASYSNOTREADY";
	case WSAVERNOTSUPPORTED          : return "WSAVERNOTSUPPORTED";
	case WSANOTINITIALISED           : return "WSANOTINITIALISED";
	case WSAEDISCON                  : return "WSAEDISCON";
	case WSAENOMORE                  : return "WSAENOMORE";
	case WSAECANCELLED               : return "WSAECANCELLED";
	case WSAEINVALIDPROCTABLE        : return "WSAEINVALIDPROCTABLE";
	case WSAEINVALIDPROVIDER         : return "WSAEINVALIDPROVIDER";
	case WSAEPROVIDERFAILEDINIT      : return "WSAEPROVIDERFAILEDINIT";
	case WSASYSCALLFAILURE           : return "WSASYSCALLFAILURE";
	case WSASERVICE_NOT_FOUND        : return "WSASERVICE_NOT_FOUND";
	case WSATYPE_NOT_FOUND           : return "WSATYPE_NOT_FOUND";
	case WSA_E_NO_MORE               : return "WSA_E_NO_MORE";
	case WSA_E_CANCELLED             : return "WSA_E_CANCELLED";
	case WSAEREFUSED                 : return "WSAEREFUSED";
	case WSAHOST_NOT_FOUND           : return "WSAHOST_NOT_FOUND";
	case WSATRY_AGAIN                : return "WSATRY_AGAIN";
	case WSANO_RECOVERY              : return "WSANO_RECOVERY";
	case WSANO_DATA                  : return "WSANO_DATA";
	case WSA_QOS_RECEIVERS           : return "WSA_QOS_RECEIVERS";
	case WSA_QOS_SENDERS             : return "WSA_QOS_SENDERS";
	case WSA_QOS_NO_SENDERS          : return "WSA_QOS_NO_SENDERS";
	case WSA_QOS_NO_RECEIVERS        : return "WSA_QOS_NO_RECEIVERS";
	case WSA_QOS_REQUEST_CONFIRMED   : return "WSA_QOS_REQUEST_CONFIRMED";
	case WSA_QOS_ADMISSION_FAILURE   : return "WSA_QOS_ADMISSION_FAILURE";
	case WSA_QOS_POLICY_FAILURE      : return "WSA_QOS_POLICY_FAILURE";
	case WSA_QOS_BAD_STYLE           : return "WSA_QOS_BAD_STYLE";
	case WSA_QOS_BAD_OBJECT          : return "WSA_QOS_BAD_OBJECT";
	case WSA_QOS_TRAFFIC_CTRL_ERROR  : return "WSA_QOS_TRAFFIC_CTRL_ERROR";
	case WSA_QOS_GENERIC_ERROR       : return "WSA_QOS_GENERIC_ERROR";
	case WSA_QOS_ESERVICETYPE        : return "WSA_QOS_ESERVICETYPE";
	case WSA_QOS_EFLOWSPEC           : return "WSA_QOS_EFLOWSPEC";
	case WSA_QOS_EPROVSPECBUF        : return "WSA_QOS_EPROVSPECBUF";
	case WSA_QOS_EFILTERSTYLE        : return "WSA_QOS_EFILTERSTYLE";
	case WSA_QOS_EFILTERTYPE         : return "WSA_QOS_EFILTERTYPE";
	case WSA_QOS_EFILTERCOUNT        : return "WSA_QOS_EFILTERCOUNT";
	case WSA_QOS_EOBJLENGTH          : return "WSA_QOS_EOBJLENGTH";
	case WSA_QOS_EFLOWCOUNT          : return "WSA_QOS_EFLOWCOUNT";
	case WSA_QOS_EUNKOWNPSOBJ        : return "WSA_QOS_EUNKOWNPSOBJ";
	case WSA_QOS_EPOLICYOBJ          : return "WSA_QOS_EPOLICYOBJ";
	case WSA_QOS_EFLOWDESC           : return "WSA_QOS_EFLOWDESC";
	case WSA_QOS_EPSFLOWSPEC         : return "WSA_QOS_EPSFLOWSPEC";
	case WSA_QOS_EPSFILTERSPEC       : return "WSA_QOS_EPSFILTERSPEC";
	case WSA_QOS_ESDMODEOBJ          : return "WSA_QOS_ESDMODEOBJ";
	case WSA_QOS_ESHAPERATEOBJ       : return "WSA_QOS_ESHAPERATEOBJ";
	case WSA_QOS_RESERVED_PETYPE     : return "WSA_QOS_RESERVED_PETYPE";
	case WSA_SECURE_HOST_NOT_FOUND   : return "WSA_SECURE_HOST_NOT_FOUND";
	case WSA_IPSEC_NAME_POLICY_ERROR : return "WSA_IPSEC_NAME_POLICY_ERROR";
	} return "";
}
#define WSALastErrorAsString _wsale_as_string(WSAGetLastError())


i32 scandir(const_Str0 dirname, struct dirent*** namelist, scandir_select_t* select, scandir_compar_t* compar)
{
	// https://github.com/sanko/fltk-2.0.x/blob/master/src/win32/scandir.c

	char findIn[MAX_PATH];
	// FIXME: Is it ok to copy MAX_PATH? Does it stop at terminator?
	strncpy_s(findIn, MAX_PATH, dirname, MAX_PATH);

	char* d = findIn + strlen(findIn);
	if(d == findIn)
		*d++ = '.';
	if(*(d-1)!='/' && *(d-1)!='\\')
		*d++ = '/';
	*d++ = '*';
	*d++ = 0;

	int nDir = 0;
	int NDir = 0;
	WIN32_FIND_DATA find;
	HANDLE h = FindFirstFile(findIn, &find);
	if(h == INVALID_HANDLE_VALUE)
	{
		unsigned long ret = GetLastError();
		if(ret != ERROR_NO_MORE_FILES)
		{
			// TODO: return some error code
			return -1;
		}
		*namelist = NULL;
		return nDir;
	}

	struct dirent** dir = 0;
	do {
		int namelen = strlen(find.cFileName);
		struct dirent* selectDir = malloc(sizeof(struct dirent) + namelen);
		selectDir->d_attr = find.dwFileAttributes;
		strcpy_s(selectDir->d_name, namelen, find.cFileName);

		if(!select || (*select)(selectDir))
		{
			if(nDir == NDir)
			{
				struct dirent** tempDir = calloc(sizeof(struct dirent*), NDir+33);
				if (NDir)
					memcpy(tempDir, dir, sizeof(struct dirent*)*NDir);
				if (dir)
					free(dir);
				dir = tempDir;
				NDir += 32;
			}
			dir[nDir] = selectDir;
			nDir++;
			dir[nDir] = 0;
		} else {
			free(selectDir);
		}
	} while(FindNextFile(h, &find));

	unsigned long ret = GetLastError();
	if (ret != ERROR_NO_MORE_FILES) {
		// TODO: return some error code
	}
	FindClose(h);

	if(compar)
	{
		qsort(dir, nDir, sizeof(*dir), compar);
	}

	*namelist = dir;
	return nDir;
}


int alphasort(const struct dirent** a, const struct dirent** b)
{
	// https://github.com/sanko/fltk-2.0.x/blob/master/src/scandir.c
	return strcmp((*a)->d_name, (*b)->d_name);
}


i32 read_entire_file(const_Str0 path, char** out_content, u32* out_content_size)
{
	HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(fh == INVALID_HANDLE_VALUE)
	{
		PRINT_ERROR("CreateFileA(%s) failed", path);
		return -1;
	}

	LARGE_INTEGER file_size;
	if(!GetFileSizeEx(fh, &file_size))
	{
		PRINT_ERROR("GetFileSizeEx() failed");
		CloseHandle(fh);
		return -1;
	}

	u32   buffer_size = file_size.LowPart;
	char* buffer      = memory_alloc(char, buffer_size);
	if(!buffer)
	{
		CloseHandle(fh);
		return -1;
	}

	DWORD read_count = 0;
	if(!ReadFile(fh, buffer, buffer_size, &read_count, NULL))
	{
		PRINT_ERROR("ReadFile() failed");
		CloseHandle(fh);
		memory_free(char, buffer, buffer_size);
		return -1;
	}

	CloseHandle(fh);
	if(read_count != buffer_size)
	{
		PRINT_ERROR("ReadFile() failed");
		memory_free(char, buffer, buffer_size);
		return -1;
	}

	*out_content      = buffer;
	*out_content_size = buffer_size;
	return 0;
}
