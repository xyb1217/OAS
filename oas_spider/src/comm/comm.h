
#ifndef _COMM_H_
#define _COMM_H_


                                
struct OCSP_REQ{
    EVP_MD *dgst;
    unsigned char *issuer_name_hash;
    unsigned char *issuer_key_hash;
    char *serial_number;
    char *ocsp_url;

    OCSP_REQ(){
        dgst = NULL;
        issuer_name_hash = NULL;
        issuer_key_hash = NULL;
        serial_number = NULL;
        ocsp_url = NULL;
    }
};


#endif

