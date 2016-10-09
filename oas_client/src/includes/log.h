#ifndef LOG_H
#define LOG_H
#include <stdint.h>

#define MAX_LOGTEXT_LINE_LEN (1024)
#define MAX_TIME_BUF_SIZE (40)

#pragma pack(push, 1)
typedef struct tagLOG_DATA
{
    char            strDate[11];
    char            strTime[9];
    short           sType;
    char            strText[MAX_LOGTEXT_LINE_LEN];
}LOG_DATA, *PLOG_DATA;
#pragma pack(pop)


typedef enum sys_log_level_em
{
    LOG_LEVEL_NONE = -1,
    LOG_LEVEL_ERR = 0,
    LOG_LEVEL_WARNING = 1,
    LOG_LEVEL_DEBUG = 2,
    LOG_LEVEL_ALWAYS = 99
}SYS_LOG_LEVEL_EM;



extern "C"{
int  init_log(short sys_log_level,const char* log_path);
void write_log_simple(short sLogType,
                      const char *file,
                      unsigned int line,
                      const char *pstrFmt, ...);
}
#define write_log(type,args...) write_log_simple(type,__FILE__, __LINE__,##args)

extern uint8_t g_loglevel;
#endif //LOG_H
