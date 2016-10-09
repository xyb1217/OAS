#ifndef THREAD_H
#define THREAD_H

#include <pthread.h>

class Thread
{
public:
    Thread(int detachstate = PTHREAD_CREATE_JOINABLE);
    bool Start();
private:
    pthread_t m_pid;
    pthread_attr_t m_atrr;
    static void * _StartThread(void *arg);
    virtual void _Run() = 0;
};



#endif // THREAD_H
