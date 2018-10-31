#include "argtable/argtable3.c"
#include "platform.h"


typedef struct CLIArgs
{
	//b32 daemonize;
	b32 is_slave;
} CLIArgs;


i32 parse_args(int argc, char** argv, CLIArgs* args)
{
	struct arg_lit* daemonize;
	struct arg_lit* is_slave;
	struct arg_end* end;

	void* argtable[] = {
		//daemonize = arg_lit0(NULL, "daemonize", "Daemonize on start"),
		is_slave  = arg_lit0(NULL, "slave",     "Internal flag"),
		end       = arg_end(20),
	};

	int error_count = arg_parse(argc, argv, argtable);
	if(error_count > 0)
	{
		arg_print_errors(stderr, end, argv[0]);
		arg_freetable(argtable, ARRAY_COUNT(argtable));
		return -1;
	}

	//args->daemonize = daemonize->count > 0;
	args->is_slave  = is_slave->count > 0;

	arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));
	return 0;
}
