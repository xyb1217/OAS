#include "spider_pool.h"


SpiderPool::SpiderPool()
{
	spider_pool_ = NULL;
	pool_size_ = 0;
}


SpiderPool::~SpiderPool()
{
	for (int i = 0; i < pool_size_; i++)
	{
		if (spider_pool_[i] != NULL){
			delete spider_pool_[i];
			spider_pool_[i] = NULL;
		}
	}

	if (spider_pool_){
		delete [] spider_pool_;
		spider_pool_ = NULL;
	}
}


bool SpiderPool::init(unsigned int pool_size, TcpSrv * tcp_srv, rcv_task_cb pcb)
{
	pool_size_ 
        = (pool_size > RCV_POOL_MAX_SIZE) ? RCV_POOL_MAX_SIZE : pool_size;

	spider_pool_ = new RcvTask *[pool_size_];
	if (!spider_pool_){
	    PRINTF("new SpiderPool error");
		return false;
	}
	
	for (int i = 0; i < pool_size_; i++)
	{
		spider_pool_[i] = new RcvTask();
		if (!spider_pool_[i]){
            PRINTF("new RcvTask error");
			return false;
		}
	}
	tcp_srv_ = tcp_srv;
    pcb_ = pcb;
	return true;
}


bool SpiderPool::dispatch(REQ_BUFFER & req_buffer)
{	
	//随机选择一个子线程，通过管道向其传递socket描述符
	int num = req_buffer.socket_id % pool_size_;
	int ret = spider_pool_[num]->write_task(req_buffer);
	if (ret != sizeof(REQ_BUFFER))
		return false;
	
	return true;
}


// 启动池开始工作
bool SpiderPool::start() 
{
	for (int i = 0; i < pool_size_; i++)
	{
		spider_pool_[i]->SetNo(i);
		char thread_name[32] = {0};
		sprintf(thread_name, "srv_thread_%d", i);
		spider_pool_[i]->SetName(thread_name);
		spider_pool_[i]->init(tcp_srv_, pcb_);
		bool bret = spider_pool_[i]->Start();
		if (!bret){
            PRINTF("start RcvTask thread(%s) error", thread_name);
			return false;
		}
		usleep(10000);
	}
	return true;
}

