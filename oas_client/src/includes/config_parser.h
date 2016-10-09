#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H
#include "genaral.h"

class ConfigParser
{
public:
    ConfigParser();
    ConfigParser(const char* configxml);
    ~ConfigParser();
    bool Parse(const char* configxml);
    const config_t* GetConfig();
private:
    config_t *m_config;
    typedef std::list<char*>::const_iterator ccter;
};

extern ConfigParser *g_config_parser;

#endif // CONFIG_PARSER_H
