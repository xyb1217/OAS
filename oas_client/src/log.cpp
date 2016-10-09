#include <time.h>
#include <memory.h>
#include <alloca.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include "log.h"


#define LOG_SUCCESS (0)
#define LOG_FAILED  (-1)
#define LOG_BOOL_TRUE (1)
#define LOG_BOOL_FALSE (0)

#define MAX_FILE_PATH (255)

const unsigned int MAX_LOG_FILE_SIZE = 2*1024*1024;

const short LOG_DATA_SIZE = sizeof(LOG_DATA);

static pthread_mutex_t k_log_mutex = PTHREAD_MUTEX_INITIALIZER ;
static short k_ssys_log_level = LOG_LEVEL_NONE;
static const char*k_log_path = NULL;

static int  _check_logfile_full();
static int _file_init( const char* log_path );
static void _save_old_log();
int write_log_text(const char *file,unsigned int line,PLOG_DATA pLogData);

int init_log(short sys_log_level,const char* log_path)
{
    if(_file_init(log_path) != 0)
        return -1;
    k_ssys_log_level = sys_log_level;
    k_log_path = log_path;
    return 0;
}

int _check_logfile_full()
{
    struct stat buf;
    if(stat(k_log_path, &buf)<0)
    {
        return 0;
    }
    else
    {
        unsigned long file_len = (unsigned long)buf.st_size;
        if(file_len > MAX_LOG_FILE_SIZE - LOG_DATA_SIZE)
        {
            return 1;
        }
        return 0;
    }
}

int _file_init( const char* log_path )
{
    int ret = 0;
    int fd = 0;

    if( !log_path )
        return ( -1 );

    if(( fd = open( log_path, O_RDWR | O_APPEND | O_CREAT | O_TRUNC,
                    S_IRUSR | S_IWUSR )) == -1 )
    {
        /* Error! */
        return( -1 );
    }

    close ( fd );
    return ( ret );
}


void _save_old_log()
{
    char *file_rename = NULL;
    if(access(k_log_path,0) == 0)
    {
        file_rename = (char*)calloc(1,256);//delete end
        if(!file_rename)
            return;
        char time_buf[MAX_TIME_BUF_SIZE]={0};
        char *time_buf_ptr = time_buf;
        time_t curTime;
        struct tm *mt;
        curTime = time(NULL);

        mt = localtime(&curTime);
        strftime(time_buf_ptr, MAX_TIME_BUF_SIZE/2, "_%Y-%m-%d", mt);
        time_buf_ptr += strlen(time_buf);
        strftime(time_buf_ptr, MAX_TIME_BUF_SIZE/2, "-%H:%M:%S", mt);

        const char *req_ptr = k_log_path;
        while( strchr( req_ptr, '.' ) != NULL )
        {
            req_ptr = strchr( req_ptr, '.' );
            req_ptr++;
        }

        if(req_ptr == k_log_path)
        {
            req_ptr += strlen(k_log_path);
        }
        else
        {
            --req_ptr;
        }
        strncpy(file_rename,k_log_path,req_ptr-k_log_path);
        strcat(file_rename,time_buf);
        strcat(file_rename,req_ptr);
        rename(k_log_path,file_rename);
        remove(k_log_path);
        free(file_rename);
    }
}



void write_log_simple(short sLogType,
                      const char *file,
                      unsigned int line,
                      const char *pstrFmt, ...)
{
    LOG_DATA data;
    time_t curTime;
    struct tm *mt;
    pthread_mutex_lock(&k_log_mutex);
    va_list v1;
    memset(&data, 0, sizeof(LOG_DATA));
    va_start(v1, pstrFmt);
    vsnprintf(data.strText, MAX_LOGTEXT_LINE_LEN, pstrFmt, v1);
    va_end(v1);
    data.sType = sLogType;
    curTime = time(NULL);
    mt = localtime(&curTime);
    strftime(data.strDate, sizeof(data.strDate), "%Y-%m-%d", mt);
    strftime(data.strTime, sizeof(data.strTime), "%H:%M:%S", mt);
    if(_check_logfile_full() == 1)
    {
        _save_old_log();
    }
    write_log_text(file,line,&data);
    pthread_mutex_unlock(&k_log_mutex);

}


int write_log_text(const char *file,unsigned int line,PLOG_DATA pLogData)
{
    static const char* str_log_err = "ERR";
    static const char* str_log_warning = "WARNING";
    static const char* str_log_debug = "DEBUG";
    static const char* str_log_always = "ALWAYS";
    if(!k_log_path)
        return LOG_FAILED;

    if(pLogData->sType != LOG_LEVEL_ALWAYS)
    {
        if(pLogData->sType > k_ssys_log_level)
            return LOG_FAILED;
    }

    const char *str_log_type = NULL;
    switch(pLogData->sType)
    {
        case LOG_LEVEL_ERR:
            {
                str_log_type = str_log_err;
                break;
            }
        case LOG_LEVEL_WARNING:
            {
                str_log_type = str_log_warning;
                break;
            }
        case LOG_LEVEL_DEBUG:
            {
                str_log_type = str_log_debug;
                break;
            }
        case LOG_LEVEL_ALWAYS:
            {
                str_log_type = str_log_always;
                break;
            }
        default:
            {
                return LOG_FAILED;
                break;
            }
    }


    FILE *pFile = NULL;
    char szLogTextLINE[MAX_LOGTEXT_LINE_LEN];
    memset(szLogTextLINE, 0, MAX_LOGTEXT_LINE_LEN);

    pFile = fopen(k_log_path, "a+");
    if(NULL == pFile)
    {
        return LOG_FAILED;
    }

    sprintf(szLogTextLINE, "<%s>%s-%s[%s:%d]::%s\r\n", str_log_type,pLogData->strDate, pLogData->strTime,file,line,
    pLogData->strText);
    fwrite(szLogTextLINE, 1, strlen(szLogTextLINE), pFile);
    fflush(pFile);
    fclose(pFile);
    return LOG_SUCCESS;
}
