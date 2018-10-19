#include <argp.h>


enum CLIKEY
{
	CLIKEY_DAEMON   = 'd',
	CLIKEY_PORTP    = 'p',
	CLIKEY_PORTC    = 'c',
	CLIKEY_SLAVES   = 's',
	CLIKEY_THREADS  = 't',
	CLIKEY_NOAUTH   = 'a',
	CLIKEY_DOCSROOT = 'r',
};


typedef struct CLIArgs
{
	b32 daemonize;
} CLIArgs;

CLIArgs global_args = {
	.daemonize     = 0,   
	// .portp         = 8080,
	// .portc         = 8081,
	// .extra_slaves  = 0,   
	// .extra_threads = 0,   
	// .noauth        = 0,   
	// .docsroot      = ".", 
};


static
struct argp_option global_argp_options[] = 
{
	{"daemonize",     CLIKEY_DAEMON,   NULL,   OPTION_ARG_OPTIONAL, "Daemonize on start", 0},
	// {"portp",         CLIKEY_PORTP,    "port", OPTION_ARG_OPTIONAL, "Plain access port", 0},
	// {"portc",         CLIKEY_PORTC,    "port", OPTION_ARG_OPTIONAL, "Encrypted access port", 0},
	// {"extra_slaves",  CLIKEY_SLAVES,   "N",    OPTION_ARG_OPTIONAL, "Number of extra listening processes", 0},
	// {"extra_threads", CLIKEY_THREADS,  "N",    OPTION_ARG_OPTIONAL, "Number of extra listening threads (per process and per port)", 0},
	// {"noauth",        CLIKEY_NOAUTH,   NULL,   OPTION_ARG_OPTIONAL, "Disable authorization check", 0},
	// {"docsroot",      CLIKEY_DOCSROOT, "path", OPTION_ARG_OPTIONAL, "Documents/commands root directory", 0},
	{ NULL }
};


static
error_t argp_parser_callback(int key, char* arg, struct argp_state* state)
{
	CLIArgs* args = (CLIArgs*)state->input;
	
	switch(key)
	{
		case CLIKEY_DAEMON:
		{
			args->daemonize = 1;
		} break;
		// case CLIKEY_PORTP:
		// {
		// 	args->portp = (u16)strtoul(arg, NULL, 0);
		// } break;
		// case CLIKEY_PORTC:
		// {
		// 	args->portc = (u16)strtoul(arg, NULL, 0);
		// } break;
		// case CLIKEY_SLAVES:
		// {
		// 	args->extra_slaves = strtoul(arg, NULL, 0);
		// } break;
		// case CLIKEY_THREADS:
		// {
		// 	args->extra_threads = strtoul(arg, NULL, 0);
		// } break;
		// case CLIKEY_NOAUTH:
		// {
		// 	args->noauth = 1;
		// } break;
		// case CLIKEY_DOCSROOT:
		// {
		// 	args->docsroot = arg;
		// } break;
		
		default:
		{
			return ARGP_ERR_UNKNOWN;
		}
	}
	
	return 0;
}


i32 parse_args(int argc, char** argv, CLIArgs* args)
{
	struct argp argp = {};
	argp.options = global_argp_options;
	argp.parser  = argp_parser_callback;
	
	if(argp_parse(&argp, argc, argv, 0, NULL, args) != 0)
	{
		return -1;
	}
	return 0;
}
