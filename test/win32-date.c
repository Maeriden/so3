#include <stdio.h>
#include <time.h>

int main(int argc, char** argv)
{
	static const char* STRFTIME_FORMAT = "%d/%b/%Y %H:%M:%S";
	time_t now = time(NULL);
	struct tm tm;
	localtime_s(&tm, &now);
	char strftime_buffer[64] = {0};
	strftime(strftime_buffer, sizeof(strftime_buffer), STRFTIME_FORMAT, &tm);
	
	fprintf(stdout, "%s\n", strftime_buffer);
	return 0;
}
