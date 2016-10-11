#ifndef _SPIDER_PO0L_H_
#define _SPIDER_PO0L_H_

#include "spider_task.h"

#define POOL_MAX_SIZE 20

class SpiderPool
{
	public:
		SpiderPool();
		~SpiderPool();
        
		bool init(unsigned int pool_size);
		bool start();

	private:
		SpiderTask **spider_pool_;
		unsigned int pool_size_;
		
};

#endif

