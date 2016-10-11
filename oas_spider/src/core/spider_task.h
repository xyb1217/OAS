
#ifndef _SPIDER_TASK_H_
#define _SPIDER_TASK_H_


#include "cm.h"


class SpiderTask  : public CThread
{
    public:
        SpiderTask(){}
        ~SpiderTask(){}

	public:
        int process();

    protected:
        void Run();

        
    private:
};


#endif