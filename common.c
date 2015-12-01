// common.c
//

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

void ssl_error_exit(const char * fmt, ... ) {
	va_list ap;
	
	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fputs(": ", stderr);
		va_end(ap);
	}
	
	ERR_print_errors_fp(stderr);
	fputc('\n', stderr);
	
	exit(EXIT_FAILURE);
}

void errno_error_exit(const char * fmt, ... ) {
	va_list ap;
	
	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fputs(": ", stderr);
		va_end(ap);
	}
	
	fputs(strerror(errno), stderr);
	fputc('\n', stderr);
	
	exit(EXIT_FAILURE);
}

void other_error_exit(const char * fmt, ... ) {
	va_list ap;
	
	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	} else
		fputs("Unknown error", stderr);

	fputc('\n', stderr);
	
	exit(EXIT_FAILURE);
}

void usage_error_exit(void) {
	extern const char * USAGE;
	
	fputs("USAGE: ", stderr);
	fputs(USAGE, stderr);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

void ssl_error(const char * fmt, ... ) {
	va_list ap;
	
	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fputs(": ", stderr);
		va_end(ap);
	}
	
	ERR_print_errors_fp(stderr);
	fputc('\n', stderr);
}

void errno_error(const char * fmt, ... ) {
	va_list ap;
	
	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fputs(": ", stderr);
		va_end(ap);
	}
	
	fputs(strerror(errno), stderr);
	fputc('\n', stderr);
}

void other_error(const char * fmt, ... ) {
	va_list ap;
	
	if (fmt != NULL) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	} else
		fputs("Unknown error", stderr);

	fputc('\n', stderr);
}
