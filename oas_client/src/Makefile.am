#AUTOMAKE_OPTIONS=foreign

sbin_PROGRAMS = ocsp_client

ocsp_client_SOURCES=	\
  	main.cpp \
    tinystr.cpp \
    tinyxml.cpp \
    tinyxmlerror.cpp \
    tinyxmlparser.cpp \
    config_parser.cpp \
    log.cpp \
    ocsp_request.cpp \
    threadpool.cpp \
    thread.cpp


EXTRA_DIST = \
	includes/*.h

INCLUDES= \
	-I./includes \
	$(my_cflags)

ocsp_client_CFLAGS= $(my_cflags)

LIBS= $(my_ldadd)












