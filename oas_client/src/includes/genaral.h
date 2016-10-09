#ifndef GENARAL_H
#define GENARAL_H
#include <malloc.h>
#include <list>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/x509.h>


typedef struct x509_cert_s
{
    X509 *x509_issuer;
    std::list<X509*> x509_clientCertList;
    char *ocspurl;
}x509_cert_t;


typedef struct cacer_s
{
    char *capath;
    char *ocspurl;
    std::list<char *> clientcer_list;

    ~cacer_s()
    {
        if(capath)
            free(capath);
        if(ocspurl)
            free(ocspurl);

        std::list<char*>::iterator iter = clientcer_list.begin();
        for(; iter != clientcer_list.end(); ++iter)
        {
            free(*iter);
            *iter = NULL;
        }
        clientcer_list.clear();
    }
}cacer_t;



typedef struct config_s
{
    char *logfile;
    char *pidfile;
    uint16_t threadpoolnum;
    uint64_t reqgroupcount;

    std::list<cacer_t*> cacer_list;

    uint32_t resetInterval;
    uint32_t printInterval;

    config_s():logfile(NULL),pidfile(NULL),threadpoolnum(1)
    {

    }

    ~config_s()
    {
        if(logfile)
        {
            free(logfile);
            logfile = NULL;
        }
        if(pidfile)
        {
            free(pidfile);
            pidfile = NULL;
        }
        cacer_list.clear();
    }
}config_t;

extern uint64_t g_uint64_request_count;
extern uint64_t g_uint64_request_count_suc;
extern uint64_t g_uint64_request_count_fail;
extern uint64_t g_uint64_request_count_last_sec;
extern uint32_t g_uint32_request_count_per_sec;
extern pthread_mutex_t g_count_mutex;
extern bool g_bconn_ret;

extern void add_request_suc_count();
extern void add_request_fail_count();
extern void calculate_avg_request_per_sec();

#endif // GENARAL_H
