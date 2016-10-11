#ifndef _OCSP_CORE_H_
#define _OCSP_CORE_H_


#include "cm.h"


class OcspCore : public CThread
{
    public:
        OcspCore(){}
        ~OcspCore(){}
        
    public:
        OCSP_CERTID *ocsp_cert_id(const EVP_MD *dgst, 
                                    const unsigned char *issuer_name_hash,
                                    const unsigned char *issuer_key_hash,
                                    const char *serial_number);

        char spider_cert_status(const OCSP_REQ & ocsp_req);
        
        

    private:
        
};



#endif

