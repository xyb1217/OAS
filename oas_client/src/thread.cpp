#include "thread.h"
#include <pthread.h>

Thread::Thread(int detachstate)
{
    pthread_attr_init (&m_atrr);
    //pthread_attr_setscope (&attr, PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setdetachstate (&m_atrr, detachstate);
}

bool Thread::Start()
{
   if(pthread_create(&m_pid,NULL,_StartThread,(void *)this) != 0)
   {
       return false;
   }
   return true;
}

void* Thread::_StartThread(void *arg)
{
   Thread *ptr = (Thread *)arg;
   ptr->_Run();
}
