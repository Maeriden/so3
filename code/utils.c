#include <string.h>
#include "platform.h"


Str0 _strN_dup0(const char* str, u32 len, const char* __file__, int __line__)
{
	Str0 dup = _memory_alloc(len+1, __file__, __line__);
	if(dup)
		memcpy(dup, str, len);
	return dup;
}
#define strN_dup0(str, len) _strN_dup0(str, len, __FILE__, __LINE__)
#define str0_dup0(str)       strN_dup0(str, strlen(str))


char* _strN_catN(const char* prefix, u32 prefix_len, const char* suffix, u32 suffix_len, const char* __file__, int __line__)
{
	char* result = _memory_alloc(prefix_len + suffix_len, __file__, __line__);
	if(result)
	{
		memcpy(result,            prefix, prefix_len);
		memcpy(result+prefix_len, suffix, suffix_len);
	}
	return result;
}
#define strN_catN(prefix, prefix_len, suffix, suffix_len) _strN_catN(prefix, prefix_len,     suffix, suffix_len,       __FILE__, __LINE__)
#define strN_cat0(prefix, prefix_len, suffix)             _strN_catN(prefix, prefix_len,     suffix, strlen(suffix)+1, __FILE__, __LINE__)
#define str0_catN(prefix,             suffix, suffix_len) _strN_catN(prefix, strlen(prefix), suffix, suffix_len,       __FILE__, __LINE__)
#define str0_cat0(prefix,             suffix)             _strN_catN(prefix, strlen(prefix), suffix, strlen(suffix)+1, __FILE__, __LINE__)


u32 strN_indexofN(const char* haystack, u32 haystack_len, const char* needle, u32 needle_len)
{
	if(haystack_len < needle_len)
		return haystack_len;
	u32 last_chance = haystack_len-needle_len;
	for(u32 h = 0; h <= last_chance; ++h)
		if(strncmp(haystack+h, needle, needle_len) == 0)
			return h;
	return haystack_len;
}
#define strN_indexof0(haystack, haystack_len, needle)             strN_indexofN(haystack, haystack_len,     needle, strlen(needle))
#define str0_indexofN(haystack,               needle, needle_len) strN_indexofN(haystack, strlen(haystack), needle, needle_len)
#define str0_indexof0(haystack,               needle)             strN_indexofN(haystack, strlen(haystack), needle, strlen(needle))


b32 strN_beginswithN(const_Str0 string, u32 string_len, const_Str0 prefix, u32 prefix_len)
{
	if(string_len < prefix_len)
		return 0;
	return strN_indexofN(string, prefix_len, prefix, prefix_len) == 0;
}
#define strN_beginswith0(string, string_len, prefix)             strN_beginswithN(string, string_len,     prefix, strlen(prefix))
#define str0_beginswithN(string,             prefix, prefix_len) strN_beginswithN(string, strlen(string), prefix, prefix_len)
#define str0_beginswith0(string,             prefix)             strN_beginswithN(string, strlen(string), prefix, strlen(prefix))


u32 strN_findlineN(const char* string, u32 string_len, const char** out_line, u32* out_line_len)
{
	*out_line     = NULL;
	*out_line_len = 0;

	if(string == NULL || string_len == 0)
		return 0;

	u32         line_len = string_len;
	const char* line     = string;
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


static
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
	Str0 config_string0 = strN_dup0(config_string, config_string_len);
	int error = ini_parse_string(config_string0, inih_handler, config);
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


i32 parse_users_string(char* users_string, u32  users_string_len, Str0** out_users, u32* out_users_count)
{
	*out_users       = NULL;
	*out_users_count = 0;

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

		if(strN_indexofN(line, line_len, ":", 1) < line_len)
			++users_count;
	}

	if(users_count == 0)
		return 0;

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

		if(strN_indexofN(line, line_len, ":", 1) == line_len)
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
