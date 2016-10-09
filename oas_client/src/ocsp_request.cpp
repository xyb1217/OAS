#include <unistd.h>
#include <openssl/e_os2.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <pthread.h>
#include "ocsp_request.h"
#include "threadpool.h"
#include "genaral.h"
#include "log.h"


#define DER			    1 //FORMAT_ASN1
#define PEM			    3	/*定义格式*/
#define NET				4
#define P12				5

pthread_mutex_t OcspRequestThread::s_openssl_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t OcspRequestThread::s_openssl_mutex1 = PTHREAD_MUTEX_INITIALIZER;

OcspRequestThread::OcspRequestThread():m_id(0),m_bio(NULL)
{

}


OcspRequestThread::~OcspRequestThread()
{


}

void OcspRequestThread::SetId(int id)
{
    m_id = id;
}

void OcspRequestThread::_Run()
{
    int nStatus = 0;
    while(1)
    {
        x509_cert_item_t *x509_cert_item = g_threadpool->GetTaskItem();
        nStatus = GetOcspRespStatus(x509_cert_item->x509_clientcert,
                          x509_cert_item->x509_issuer,
                          x509_cert_item->ocspurl);

        //check status
        if(nStatus == -1)
        {
            add_request_fail_count();
            char *seriaStr = i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(x509_cert_item->x509_clientcert));
            write_log(LOG_LEVEL_DEBUG,"%d thread --> certificate(%s) resp status err",m_id,seriaStr);
            free(seriaStr);
        }
        else if(nStatus == 0)
        {
            add_request_suc_count();
            char *seriaStr = i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(x509_cert_item->x509_clientcert));
            write_log(LOG_LEVEL_DEBUG,"%d thread --> certificate(%s)status: Good",m_id,seriaStr);
            free(seriaStr);
        }
        else if(nStatus == 1)
        {
            add_request_suc_count();
            char *seriaStr = i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(x509_cert_item->x509_clientcert));
            write_log(LOG_LEVEL_DEBUG,"%d thread --> certificate(%s) status: Revoked",m_id,seriaStr);
            free(seriaStr);
        }
        else
        {
            add_request_fail_count();
            char *seriaStr = i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(x509_cert_item->x509_clientcert));
            write_log(LOG_LEVEL_DEBUG,"%d thread --> certificate(%s) status: Unknown",m_id,seriaStr);
            free(seriaStr);
        }
        delete x509_cert_item;
    }
}

/*-------------------------------------------------*
*   方法：GetOcspRespStatus                           *
*   说明：OCSP验证数字证书                            *
*   参数：输入为X509                                 *
*--------------------------------------------------*/
int OcspRequestThread::GetOcspRespStatus(X509* pCert, X509* pIssuer, char* szOcspUrl)
{

    if(pCert==NULL || pIssuer==NULL)
    {
        write_log(LOG_LEVEL_ERR,"pCert==NULL || pIssuer==NULL");
		printf("pCert==NULL || pIssuer==NULL\n");
        return -1;
    }

    //OCSP
    int                   rc, reason, ssl, status = -1;
    char                  *host = 0, *path = 0, *port = 0;
    OCSP_CERTID           *id;
    OCSP_REQUEST          *req = 0;
    OCSP_RESPONSE         *resp = 0;
    OCSP_BASICRESP        *basic = 0;
    ASN1_GENERALIZEDTIME  *producedAt, *thisUpdate, *nextUpdate;
    int tryNum = 5;

    //Parse URL
    if(!OCSP_parse_url(szOcspUrl, &host, &port, &path, &ssl))
    {
        write_log(LOG_LEVEL_ERR,"OCSP_parse_url err");
        goto end;
    }

    //NEW Request
    if(!(req = OCSP_REQUEST_new()))
    {
        write_log(LOG_LEVEL_ERR,"OCSP_REQUEST_new err");
        goto end;
    }

    //CertID
    id = OCSP_cert_to_id(NULL, pCert, pIssuer);
    if(!id)
    {
        write_log(LOG_LEVEL_ERR,"id == NULL");
        goto end;
    }

    if(!OCSP_request_add0_id(req, id))
    {
        char strErr[256] = {0};
        write_log(LOG_LEVEL_ERR,"OCSP_request_add0_id err:%s",
                  ERR_error_string(ERR_get_error(), strErr));
        goto end;
    }

    OCSP_request_add1_nonce(req, NULL, -1);

    //bio connection
    if(!m_bio)
    {
        BIO_METHOD *bio_method = BIO_s_connect();
        m_bio = BIO_new(bio_method);

        if(!m_bio)
        {
            char strErr[256] = {0};
            write_log(LOG_LEVEL_ERR,"BIO_new err:%s",
                      ERR_error_string(ERR_get_error(), strErr));
            goto end;
        }
        BIO_set_flags(m_bio,BIO_CONN_S_BLOCKED_CONNECT);
        BIO_set_conn_hostname(m_bio,host);
        BIO_set_conn_port(m_bio, port);
    }

    tryNum = 1;
    while(tryNum != 0)
    {
        pthread_mutex_lock(&s_openssl_mutex);
        int ret = BIO_do_connect(m_bio);
        pthread_mutex_unlock(&s_openssl_mutex);
        if(ret <= 0)
        {
            BIO_reset(m_bio);
            //BIO_free_all(m_bio);
            //m_bio = NULL;
            usleep(10000);
            --tryNum;
        }
        else
            break;
    }
    if(tryNum == 0)
    {
        char strErr[256] = {0};
        if(g_bconn_ret)
        {
            write_log(LOG_LEVEL_ERR,"BIO_do_connect err:%s",
                      ERR_error_string(ERR_get_error(), strErr));
            g_bconn_ret = false;
        }
        goto end;
    }

    g_bconn_ret = true;
    //send request
    try
    {
        //send the request and get a response
        tryNum = 1;
        while(tryNum != 0)
        {
            pthread_mutex_lock(&s_openssl_mutex1);
            resp = OCSP_sendreq_bio(m_bio, path, req);
            pthread_mutex_unlock(&s_openssl_mutex1);
            if(!resp)
            {
            	//printf("resp:%s\n",*resp);
                BIO_reset(m_bio);
                //BIO_free_all(m_bio);
                //m_bio = NULL;
                usleep(10000);
                --tryNum;
            }
            else
                break;
        }
        if(tryNum == 0)
        {
            char strErr[256] = {0};
            write_log(LOG_LEVEL_ERR,"OCSP_sendreq_bio err:%s",
                      ERR_error_string(ERR_get_error(), strErr));
            goto end;
        }

        if((rc = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
        {
            char strErr[256] = {0};
            write_log(LOG_LEVEL_ERR,"OCSP_response_status err:%s",
                      ERR_error_string(ERR_get_error(), strErr));
            goto end;
        }
		printf("rc:%d\n",rc);
        //Get basic
        if (!(basic = OCSP_response_get1_basic(resp)))
        {
            char strErr[256] = {0};
            write_log(LOG_LEVEL_ERR,"OCSP_response_get1_basic err:%s",
                      ERR_error_string(ERR_get_error(), strErr));
            goto end;
        }

        //Get Status
        if (!OCSP_resp_find_status(basic, id, &status, &reason, &producedAt,&thisUpdate, &nextUpdate))
        {
            char strErr[256] = {0};
            write_log(LOG_LEVEL_ERR,"OCSP_resp_find_status err:%s",
                      ERR_error_string(ERR_get_error(), strErr));
            goto end;
        }
    }
    catch(...)
    {
        write_log(LOG_LEVEL_ERR,"try err");
        goto end;
    }

end:
    if (m_bio)
    {
        BIO_free(m_bio);
        m_bio = NULL;
    }
    if (host) OPENSSL_free(host);
    if (port) OPENSSL_free(port);
    if (path) OPENSSL_free(path);
    if (req) OCSP_REQUEST_free(req);
    if (resp) OCSP_RESPONSE_free(resp);
    if (basic) OCSP_BASICRESP_free(basic);
    return status;
}

/*-------------------------------------------------*
*   方法：load_cert_bio                            *
*   说明：将DER、PEM、P12文件公钥读出来 输入BIO    *
*   参数： 1.输入BIO / 2.格式 / 3.P12密码          *
*--------------------------------------------------*/
X509* OcspRequestThread::_LoadCertBio(BIO * pBioCert, const int iFormat,const char * lpszPwd)
{
    X509  *x = NULL;
    if(iFormat == DER)
    {
        x = d2i_X509_bio(pBioCert,NULL);
    }
    else if(iFormat == PEM)
    {
        x = PEM_read_bio_X509(pBioCert,NULL,NULL,NULL); //PEM_read_bio_X509_AUX
    }
    else if(iFormat == P12)
    {
        OpenSSL_add_all_algorithms();
        PKCS12 *p12 = d2i_PKCS12_bio(pBioCert, NULL);
        PKCS12_parse(p12, lpszPwd, NULL, &x, NULL);
        PKCS12_free(p12);
        p12 = NULL;
    }
    else
    {
        write_log(LOG_LEVEL_ERR,"bad input format specified for input cert\n");
        if(x == NULL)
        {
            write_log(LOG_LEVEL_ERR,"unable to load certificate\n");
        }
        else
        {
            write_log(LOG_LEVEL_DEBUG,"OK\n");
        }
    }

    return(x);
}


/*-------------------------------------------------*
*   方法：LoadCertEx                                *
*   说明：加载证书到X509中 DER/PEM 自动匹配格式          *
*--------------------------------------------------*/
X509* OcspRequestThread::LoadCert(const char * lpszCert,const int iCertlen,const char *lpszPass)
{
	printf("lpszCert:%s\n",lpszCert);
	printf("lpszPass:%s\n",lpszPass);
	printf("iCertlen:%d\n",iCertlen);
    BIO *in = NULL;
    X509    *x509 = NULL;

    if(iCertlen == 0)  //输入为磁盘文件
    {
        if((in = BIO_new_file(lpszCert, "r")) == NULL)
        {
            write_log(LOG_LEVEL_ERR,"open CA certificate file error");
			printf("325 open CA certificate file error\n");
            return NULL;
        }
    }
    else //输入为内存中文件
    {
        if((in = BIO_new_mem_buf((void *)lpszCert,iCertlen)) == NULL)  //只读类型
        {
            write_log(LOG_LEVEL_ERR,"Make Mem Bio Error");
            return NULL;
        }
    }
    if((x509 = _LoadCertBio(in,DER,NULL)) == NULL)  //尝试DER
    {
        BIO_reset(in);   //恢复bio
        if((x509 = _LoadCertBio(in,PEM,NULL)) == NULL)//尝试PEM
        {
            BIO_reset(in); //恢复bio
            x509 = _LoadCertBio(in,P12,lpszPass);//尝试P12
        }
    }
    if (in != NULL)
    {
        BIO_free(in);
    }
    return x509;
}
