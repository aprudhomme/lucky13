// common.h
//

#ifndef _HW4_H_
#define _HW4_H_

#ifdef __cplusplus
extern "C" {
#endif

extern void errno_error_exit(const char * fmt, ... );
extern void ssl_error_exit(const char * fmt, ... );
extern void other_error_exit(const char * fmt, ... );
extern void usage_error_exit(void);

extern void errno_error(const char * fmt, ... );
extern void ssl_error(const char * fmt, ... );
extern void other_error(const char * fmt, ... );

#ifdef __cplusplus
}
#endif

#endif
