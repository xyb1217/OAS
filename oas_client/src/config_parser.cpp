#include <stdlib.h>
#include <iostream>
#include "config_parser.h"
#include "genaral.h"
#include "tinyxml.h"

ConfigParser::ConfigParser():m_config(new config_t())
{

}

ConfigParser::ConfigParser(const char* configxml)
        :m_config(new config_t)
{
    Parse(configxml);
}


ConfigParser::~ConfigParser()
{
    if(m_config)
    {
        delete m_config;
        m_config = NULL;
    }
}

const config_t* ConfigParser::GetConfig()
{
    return m_config;
}


bool ConfigParser::Parse(const char* configxml)
{
    if(configxml == NULL)
    {
        return false;
    }
    TiXmlDocument *myDocument = new TiXmlDocument();
    if(myDocument == NULL)
    {
        return false;
    }
    myDocument->LoadFile(configxml);
    TiXmlElement *rootEle = myDocument->RootElement();
    if(!rootEle)
    {
        std::cerr<<"rootEle NULL!"<<std::endl;
        goto err;
    }
    else
    {
        TiXmlElement *generalEle = rootEle->FirstChildElement("general");
        if(!generalEle)
        {
            std::cerr<<"generalEle NULL!"<<std::endl;
            goto err;
        }
        else
        {
            TiXmlElement *logfileEle = generalEle->FirstChildElement("logfile");
            if(logfileEle)
            {
                m_config->logfile = strdup(logfileEle->GetText());
            }

            TiXmlElement *pidfileEle = generalEle->FirstChildElement("pidfile");
            if(pidfileEle)
            {
                m_config->pidfile = strdup(pidfileEle->GetText());
            }

            TiXmlElement *threadpoolnumEle = generalEle->FirstChildElement("threadpoolsize");
            if(threadpoolnumEle)
            {
                m_config->threadpoolnum = atoi(threadpoolnumEle->GetText());
            }

            TiXmlElement *reqgroupcountEle = generalEle->FirstChildElement("reqgroupcount");
            if(reqgroupcountEle)
            {
                m_config->reqgroupcount = atoi(reqgroupcountEle->GetText());
            }
        }

        TiXmlElement *cerEle = rootEle->FirstChildElement("cer");
        if(!cerEle)
        {
            std::cerr<<"cerEle NULL!"<<std::endl;
            goto err;
        }
        else
        {
            TiXmlElement *cacerEle = cerEle->FirstChildElement("cacer");
            while(cacerEle)
            {
                cacer_t *cacer = new cacer_t;
                TiXmlAttribute *cacerdir= cacerEle->FirstAttribute();
                if(cacerdir)
                {
                    cacer->capath = strdup(cacerdir->Value());
                }

                TiXmlAttribute *ocspurl = cacerEle->LastAttribute();
                if(ocspurl)
                {
                    cacer->ocspurl = strdup(ocspurl->Value());
                }

                TiXmlElement *clientcerEle = cacerEle->FirstChildElement("clientcer");
                while(clientcerEle)
                {
                    char *clientcer = strdup(clientcerEle->GetText());
                    cacer->clientcer_list.push_back(clientcer);
                    clientcerEle = clientcerEle->NextSiblingElement();
                }
                m_config->cacer_list.push_back(cacer);
                cacerEle = cacerEle->NextSiblingElement();
            }
        }

        TiXmlElement *logEle = rootEle->FirstChildElement("log");
        if(!logEle)
        {
            std::cerr<<"logEle NULL!"<<std::endl;
            goto err;
        }
        else
        {
            TiXmlElement *resetIntervalEle = logEle->FirstChildElement("resetInterval");
            if(!resetIntervalEle)
            {
                std::cerr<<"resetIntervalEle NULL!"<<std::endl;
                goto err;
            }
            else
            {
                m_config->resetInterval = atoi(resetIntervalEle->GetText());
            }

            TiXmlElement *printIntervalEle = logEle->FirstChildElement("printInterval");
            if(!printIntervalEle)
            {
                std::cerr<<"printIntervalEle NULL!"<<std::endl;
                goto err;
            }
            else
            {
                m_config->printInterval = atoi(printIntervalEle->GetText());
            }
        }
    }
    if(myDocument)
        delete myDocument;
    return true;
err:
    if(myDocument)
        delete myDocument;
    return false;

}
