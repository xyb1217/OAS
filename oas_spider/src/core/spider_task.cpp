
#include "ocsp_core.h"


int SpiderTask::process(const OCSP_REQ & ocsp_req)
{
    OcspCore ocsp_core;
    ocsp_core.spider_cert_status(ocsp_req);


    
    return 0;
}


void SpiderTask::Run()
{
    while (1){
        process();
    }
    
    return;
}

