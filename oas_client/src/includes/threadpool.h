#ifndef THREADPOOL_H
#define THREADPOOL_H
#include <stdint.h>
#include <list>
#include <pthread.h>
#include "genaral.h"

class OcspRequestThread;

typedef struct x509_cert_item_s
{
    X509 *x509_issuer;
    X509 *x509_clientcert;
    char *ocspurl;
}x509_cert_item_t;



class ThreadPool
{
public:
    ThreadPool(int threadpoolsize);
    ~ThreadPool();
    void Start();
    void InsertTask(x509_cert_t *x509_cert,uint64_t &taskcount);
    x509_cert_item_t *GetTaskItem();
    bool IsTaskEmpty();
    uint64_t GetConsumeTaskCount();
    uint64_t GetConsumeTaskCountAndReset();
private:
    static pthread_mutex_t s_task_mutex;
    static pthread_cond_t s_task_cond;

    uint16_t m_threadpoolsize;
    uint64_t m_consumeTaskCount;

    OcspRequestThread *m_szOcspRequestThread;

    std::list<x509_cert_item_t*> m_tasklist;
};


extern ThreadPool *g_threadpool;
#endif // THREADPOOL_H
