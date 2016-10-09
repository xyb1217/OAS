#ifndef OCSP_REQUEST_H
#define OCSP_REQUEST_H
#include "thread.h"
#include <openssl/x509.h>

class OcspRequestThread : public Thread
{
public:
    OcspRequestThread();
    ~OcspRequestThread();

    void SetId(int id);
    int GetOcspRespStatus(X509* pCert,
                          X509* pIssuer,
                          char* szOcspUrl);
    static X509* LoadCert(const char * lpszCert,
                        const int iCertlen,
                        const char *lpszPass);
private:
    void _Run();
    static X509* _LoadCertBio(BIO * pBioCert,
                              const int iFormat,
                              const char * lpszPwd);

    int m_id;
    BIO  *m_bio;
    static pthread_mutex_t s_openssl_mutex;
    static pthread_mutex_t s_openssl_mutex1;

};



#endif // OCSP_REQUEST_H
