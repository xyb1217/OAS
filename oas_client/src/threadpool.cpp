#include <unistd.h>
#include "threadpool.h"
#include "ocsp_request.h"
#include "genaral.h"


pthread_mutex_t ThreadPool::s_task_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ThreadPool::s_task_cond = PTHREAD_COND_INITIALIZER;

ThreadPool::ThreadPool(int threadpoolsize)
    :m_threadpoolsize(threadpoolsize),
     m_consumeTaskCount(0)
{
    m_szOcspRequestThread = new OcspRequestThread[m_threadpoolsize];
    m_tasklist.clear();
}


ThreadPool::~ThreadPool()
{

}

void ThreadPool::Start()
{
    int i = 0;
    for(i=0; i < m_threadpoolsize; ++i)
    {
        m_szOcspRequestThread[i].SetId(i);
        m_szOcspRequestThread[i].Start();
        usleep(1000);
    }
}


void ThreadPool::InsertTask(x509_cert_t *x509_cert,uint64_t &taskcount)
{
    if(!x509_cert)
        return;

    std::list<X509*>::const_iterator citer = x509_cert->x509_clientCertList.begin();
    for(citer; citer != x509_cert->x509_clientCertList.end(); ++citer)
    {
        x509_cert_item_t *item = new x509_cert_item_t;
        item->x509_issuer = x509_cert->x509_issuer;
        item->x509_clientcert = (*citer);
        item->ocspurl = x509_cert->ocspurl;

        pthread_mutex_lock(&s_task_mutex);
        m_tasklist.push_back(item);
        ++taskcount;
        pthread_cond_broadcast(&s_task_cond);
        pthread_mutex_unlock(&s_task_mutex);
    }
}

uint64_t ThreadPool::GetConsumeTaskCountAndReset()
{
    pthread_mutex_lock(&s_task_mutex);
    uint64_t count = m_consumeTaskCount;
    m_consumeTaskCount = 0;
    pthread_mutex_unlock(&s_task_mutex);
    return count;
}

uint64_t ThreadPool::GetConsumeTaskCount()
{
    return m_consumeTaskCount;
}

bool ThreadPool::IsTaskEmpty()
{
    bool flag;
    pthread_mutex_lock(&s_task_mutex);
    flag = m_tasklist.empty();
    pthread_mutex_unlock(&s_task_mutex);
    return flag;
}

x509_cert_item_t *ThreadPool::GetTaskItem()
{
    pthread_mutex_lock(&s_task_mutex);
    while(m_tasklist.empty())
    {
        pthread_cond_wait(&s_task_cond,&s_task_mutex);
    }
    x509_cert_item_t *item = m_tasklist.front();
    m_tasklist.pop_front();
    ++m_consumeTaskCount;
    pthread_mutex_unlock(&s_task_mutex);
    return item;
}
