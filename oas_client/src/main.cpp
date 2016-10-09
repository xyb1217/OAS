#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <bits/siginfo.h>
#include <bits/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include "config_parser.h"
#include "ocsp_request.h"
#include "threadpool.h"
#include "log.h"

#define PID_FILE_PATH  "/tmp/ocsp_client.pid"

uint8_t g_loglevel = LOG_LEVEL_ERR;
ConfigParser *g_config_parser = NULL;
ThreadPool *g_threadpool = NULL;

uint64_t g_uint64_request_count = 0;
uint64_t g_uint64_request_count_suc = 0;
uint64_t g_uint64_request_count_fail = 0;
uint64_t g_uint64_request_count_last_sec = 0;
uint32_t g_uint32_request_count_per_sec = 0;
bool g_bconn_ret = false;
pthread_mutex_t g_count_mutex = PTHREAD_MUTEX_INITIALIZER;

int write_pid ( int pid, const char *pidfile );
void _handle_sigterm_print(union sigval i);
void _handle_sigterm_reset(union sigval i);

void show_usage(void)
{
    static const char *usage =
    "USAGE: ocsp proxy [-c -d -v] -c *.xml -d -v...\n "
    "-c      config file\n"
    "-d      daemon run\n"
    "-v      debug\n";
    printf("%s\n", usage);
}

void add_request_suc_count()
{
    pthread_mutex_lock(&g_count_mutex);
    ++g_uint64_request_count;
    ++g_uint64_request_count_suc;
    pthread_mutex_unlock(&g_count_mutex);
}

void add_request_fail_count()
{
    pthread_mutex_lock(&g_count_mutex);
    ++g_uint64_request_count;
    ++g_uint64_request_count_fail;
    pthread_mutex_unlock(&g_count_mutex);
}

void calculate_avg_request_per_sec()
{
    pthread_mutex_lock(&g_count_mutex);
    g_uint32_request_count_per_sec = g_uint64_request_count - g_uint64_request_count_last_sec;
    g_uint64_request_count_last_sec = g_uint64_request_count;
    pthread_mutex_unlock(&g_count_mutex);
}


int _create_timer (uint64_t seconds, void func(union sigval),int id)
{
    timer_t tid;
    struct sigevent se;
    struct itimerspec ts, ots;
    memset (&se, 0, sizeof (se));

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_notify_function = func;
    se.sigev_value.sival_int = id;

    if(timer_create(CLOCK_REALTIME, &se, &tid) < 0)
    {
        write_log(LOG_LEVEL_ERR,"timer_creat");
        return -1;
    }

    write_log(LOG_LEVEL_DEBUG,"timer_create successfully.");
    ts.it_value.tv_sec = 1;
    ts.it_value.tv_nsec = 0;
    ts.it_interval.tv_sec = seconds;
    ts.it_interval.tv_nsec = 0;
    if(timer_settime (tid, TIMER_ABSTIME, &ts, &ots) < 0)
    {
        write_log(LOG_LEVEL_ERR,"timer_settime");
        return -1;
    }
    return 0;
}


int main(int argc,char **argv)
{
    char *configfile = NULL;   //config file
    bool daemon = false;
    int opt_ret;

    while((opt_ret = getopt(argc,argv,"c:dv")) != EOF)
    {
        switch(opt_ret)
        {
            case 'c':
                {
                    configfile = strdup(optarg);
                    break;
                }
            case 'd':
                {
                    daemon = true;
                    break;
                }
            case 'v':
                {
                    g_loglevel = LOG_LEVEL_DEBUG;
                    break;
                }
            default:
                show_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    g_config_parser = new ConfigParser();
    if(g_config_parser == NULL)
    {
        perror("new ConfigParser fail!");
        exit(EXIT_FAILURE);
    }
    bool retParse = g_config_parser->Parse(configfile);
    if(!retParse)
    {
        perror("parse xml fail!");
        exit(EXIT_FAILURE);
    }

    const config_t *config = g_config_parser->GetConfig();
    if(!config || !config->logfile ||
            config->threadpoolnum <= 0 )
    {
        perror("config parse err!");
        exit(EXIT_FAILURE);
    }

    //init log
    int init_log_ret = init_log(g_loglevel,config->logfile);
    if(init_log_ret == -1)
    {
        perror("init log fail!");
        exit(EXIT_FAILURE);
    }

    if( daemon )
    {
        pid_t pid = fork();
        if( pid == 0 )
        {
            /* Main process, we have to save the pid to the
             * pidfile and then exit */
            if(setsid() < 0)
            {
                perror("setsid() < 0");
                return -1;
            }
            pid_t pid_1;
            pid_1 = fork();
            if(pid_1 == 0)
            {
                if(chdir("/") == -1)
                {
                    perror("chdir == -1");
                    return -1;
                }

                int null_fd;

                //将标准输入输出重定向到空设备
                null_fd = open ("/dev/null", O_RDWR, 0);
                if (null_fd != -1)
                {
                    dup2 (null_fd, STDIN_FILENO);
                    dup2 (null_fd, STDOUT_FILENO);
                    dup2 (null_fd, STDERR_FILENO);
                }

                int fdtablesize,fd;
                for (fd = 3, fdtablesize = getdtablesize(); fd < fdtablesize; fd++)
                {
                   close(fd);
                }
                umask(0);/*重设文件创建掩模 */
            }
            else if(pid_1 > 0)
            {
                return 0;
            }
            else
            {
                perror("Error While fork child!");
                return -1;
            }

            write_pid( getpid(), config->pidfile );
        }
        else if ( pid > 0 )
        {
            /* Nop */
            return 0;
        }
        else
        {
            perror("Error While spawning child!");
            return -1;
        }
    }
    else
    {
        pid_t ppid = getpid();
        write_pid( ppid, config->pidfile);
    }

    _create_timer(config->resetInterval,_handle_sigterm_reset,1);
    _create_timer(config->printInterval,_handle_sigterm_print,2);

	printf("config->resetInterval:%d\n",config->resetInterval);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    x509_cert_t *sz_x509_cert = NULL;
    int caCount = config->cacer_list.size();
	printf("-----caCount:%d\n",caCount);

    sz_x509_cert = new x509_cert_t[caCount];

    std::list<cacer_t*>::const_iterator citer = config->cacer_list.begin();
    int i = 0;
    for(citer,i=0; citer != config->cacer_list.end(); ++citer,++i)
    {
        char *issuerPath = (*citer)->capath;
		printf("issuerPath:%s----i:%d\n", issuerPath,i);
        sz_x509_cert[i].x509_issuer = OcspRequestThread::LoadCert(issuerPath,0,NULL);
        std::list<char *>::iterator client_iter = (*citer)->clientcer_list.begin();
        std::list<char *>::iterator client_iter_end = (*citer)->clientcer_list.end();
        for(client_iter; client_iter != client_iter_end; ++client_iter)
        {
            X509 *x509_clientCert = OcspRequestThread::LoadCert((*client_iter),0,NULL);
            sz_x509_cert[i].x509_clientCertList.push_back(x509_clientCert);
        }
        sz_x509_cert[i].ocspurl = (*citer)->ocspurl;
    }

    //屏蔽子线程发出SIGALRM信号和SIGBLOCK
    sigset_t ipc_mask;
    sigemptyset(&ipc_mask);
    sigaddset(&ipc_mask, SIGALRM);
    sigaddset(&ipc_mask, SIGPIPE);
    sigaddset(&ipc_mask, SIGCHLD);
    pthread_sigmask(SIG_BLOCK,&ipc_mask,NULL);

    g_threadpool = new ThreadPool(config->threadpoolnum);
    g_threadpool->Start();
    uint64_t reqgroupIndex = 1;
    uint64_t taskcount = 0;
    uint64_t consumecount = 0;
    printf("config->reqgroupcount:%d\n",config->reqgroupcount);
    if(config->reqgroupcount == 0)
    {
        while(1)
        {
            consumecount = g_threadpool->GetConsumeTaskCount();
			printf("consumecount:%d--caCount:%d--taskcount:%d\n", consumecount, caCount, taskcount);
			
            if(taskcount - consumecount > 10000)
            {
                if(taskcount > 50000)
                {
                    taskcount = taskcount - g_threadpool->GetConsumeTaskCountAndReset();
                    consumecount = 0;
                }
                sleep(1);
                continue;
            }
            for(int i=0; i<caCount; ++i)
            {
                g_threadpool->InsertTask(&sz_x509_cert[i],taskcount);
            }
            if(!g_bconn_ret)
            {
                sleep(5);
            }
        }

    }
    else if(config->reqgroupcount > 0)
    {
        while(reqgroupIndex <= config->reqgroupcount)
        {
            consumecount = g_threadpool->GetConsumeTaskCount();
            if(taskcount - consumecount > 10000)
            {
                sleep(1);
                continue;
            }
            for(int i=0; i<caCount; ++i)
            {
                g_threadpool->InsertTask(&sz_x509_cert[i],taskcount);
            }
            ++reqgroupIndex;
            if(!g_bconn_ret)
            {
                sleep(5);
            }
        }
        write_log(LOG_LEVEL_ALWAYS,"task insert end:%ld",taskcount);
        while(!g_threadpool->IsTaskEmpty())
        {
            sleep(2);
        }
    }
    else
    {
        write_log(LOG_LEVEL_ERR,"group count < 0");
    }

    union sigval sigv;
    _handle_sigterm_print(sigv);
    write_log(LOG_LEVEL_ALWAYS,"process(%d) exit...",getpid());
    return 0;
}


void _handle_sigterm_print(union sigval i)
{
    calculate_avg_request_per_sec();
    write_log(LOG_LEVEL_ALWAYS,"total: %-18llu      ok: %-18llu      fail: %-18llu          avg/s: %-10u",
            g_uint64_request_count,
            g_uint64_request_count_suc,
            g_uint64_request_count_fail,
            g_uint32_request_count_per_sec/g_config_parser->GetConfig()->printInterval);
    return;
}

void _handle_sigterm_reset(union sigval i)
{
    pthread_mutex_lock(&g_count_mutex);
    g_uint32_request_count_per_sec = g_uint64_request_count - g_uint64_request_count_last_sec;
    g_uint64_request_count_last_sec = g_uint64_request_count;
    write_log(LOG_LEVEL_ALWAYS,"total: %-18llu      ok: %-18llu      fail: %-18llu          avg/s: %-10u",
            g_uint64_request_count,
            g_uint64_request_count_suc,
            g_uint64_request_count_fail,
            g_uint32_request_count_per_sec/g_config_parser->GetConfig()->printInterval);

    write_log(LOG_LEVEL_ALWAYS,"reset request count...");
    g_uint64_request_count = 0;
    g_uint64_request_count_suc = 0;
    g_uint64_request_count_fail = 0;
    g_uint64_request_count_last_sec = 0;
    g_uint32_request_count_per_sec = 0;
    pthread_mutex_unlock(&g_count_mutex);
    return;
}


int write_pid ( int pid, const char *pidfile )
{
    FILE *fp = NULL;

    if( !pidfile )
    {
        if((fp = fopen( PID_FILE_PATH, "w" )) == NULL )
        {
            write_log(LOG_LEVEL_ERR,"open pid file err:%s",strerror(errno));
            return(-1);
        }
    }
    else
    {
        if((fp = fopen( pidfile, "w" )) == NULL )
        {
            write_log(LOG_LEVEL_ERR,"open pid file err:%s",strerror(errno));
            return(-1);
        }
    }

    fprintf( fp, "%d", pid);
    fclose( fp );

    return(0);
}


