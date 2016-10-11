



OCSP_CERTID *OcspCore::OCSP_cert_id_new(const EVP_MD *dgst,
                                        const char * issuer_name_hash,
                                        const char * issuer_key_hash,
                                        const char * serial_number)
{
    int nid;
    X509_ALGOR *alg;
    OCSP_CERTID *cid = NULL;
    ASN1_INTEGER *sn = NULL;

    if (!(cid = OCSP_CERTID_new()))
        goto err;

    alg = cid->hashAlgorithm;
    if (alg->algorithm != NULL)
        ASN1_OBJECT_free(alg->algorithm);
    
    if ((nid = EVP_MD_type(dgst)) == NID_undef) {
        goto err;
    }
    
    if (!(alg->algorithm = OBJ_nid2obj(nid)))
        goto err;
    if ((alg->parameter = ASN1_TYPE_new()) == NULL)
        goto err;
    alg->parameter->type = V_ASN1_NULL;

    if (!(ASN1_OCTET_STRING_set(cid->issuerNameHash, 
                                issuer_name_hash, 
                                strlen(issuer_name_hash))))
        goto err;

    if (!(ASN1_OCTET_STRING_set(cid->issuerKeyHash, 
                                issuer_key_hash, 
                                strlen(issuer_key_hash))))
        goto err;

    
    sn = s2i_ASN1_INTEGER(NULL, serial_number);
    if (!(cid->serialNumber = ASN1_INTEGER_dup(sn)))
        goto err;
        
    return cid;
        
 err:
    if (cid)
        OCSP_CERTID_free(cid);
    
    return NULL;
}



char OcspCore::spider_cert_status(const OCSP_REQ & ocsp_req)
{
    //OCSP
    int                   rc, reason, ssl, status = -1;
    char                  *host = NULL, *path = NULL, *port = NULL;
    OCSP_CERTID           *id = NULL;
    OCSP_REQUEST          *req = NULL;
    OCSP_RESPONSE         *resp = NULL;
    OCSP_BASICRESP        *basic = NULL;
    ASN1_GENERALIZEDTIME  *producedAt=NULL, *thisUpdate=NULL, *nextUpdate=NULL;

    
    BIO  *bio = NULL;

    //Parse URL
    if (!OCSP_parse_url(ocsp_req.ocsp_url, &host, &port, &path, &ssl))
    {
        goto end;
    }

    //NEW Request
    if (!(req = OCSP_REQUEST_new()))
    {
        goto end;
    }
    
    id = OCSP_cert_id_new(ocsp_req.dgst, ocsp_req.issuer_name_hash,
                        ocsp_req.issuer_key_hash, ocsp_req.serial_number);
    if (!id){
        goto end;
    }

    if (!OCSP_request_add0_id(req, id))
    {
        goto end;
    }

    OCSP_request_add1_nonce(req, NULL, -1);

    //bio connection
    if (!bio){
        BIO_METHOD *bio_method = BIO_s_connect();
        bio = BIO_new(bio_method);

        if(!bio){
            goto end;
        }
        
        BIO_set_flags(bio,BIO_CONN_S_BLOCKED_CONNECT);
        BIO_set_conn_hostname(bio,host);
        BIO_set_conn_port(bio, port);
    }


    int try_num = 1;
    while (try_num != 0){
        int ret = BIO_do_connect(bio);
        if (ret <= 0) {
            BIO_reset(bio);
            usleep(1000 * 10);
            --try_num;
        }
        else
            break;
    }
    
    if (try_num == 0)
    {
        goto end;
    }

    //send request
    //send the request and get a response
    try_num = 1;
    while (try_num != 0)
    {
        resp = OCSP_sendreq_bio(bio, path, req);
        if (!resp)
        {
            BIO_reset(bio);
            usleep(1000 * 10);
            --try_num;
        }
        else
            break;
    }
    
    if(try_num == 0)
    {
        goto end;
    }

    if ((rc = OCSP_response_status(resp)) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
    {
        goto end;
    }
	printf("rc:%d\n",rc);
    
    //Get basic
    if (!(basic = OCSP_response_get1_basic(resp)))
    {
        goto end;
    }

    //Get Status
    if (!OCSP_resp_find_status(basic, id, &status, &reason, &producedAt, &thisUpdate, &nextUpdate))
    {
        goto end;
    }
    

end:
    if (bio){
        BIO_free(bio);
        bio = NULL;
    }
    
    if (host) OPENSSL_free(host);
    if (port) OPENSSL_free(port);
    if (path) OPENSSL_free(path);
    if (req) OCSP_REQUEST_free(req);
    if (resp) OCSP_RESPONSE_free(resp);
    if (basic) OCSP_BASICRESP_free(basic);
    return status;
}

