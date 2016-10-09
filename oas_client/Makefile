

###################项目路径和程序名称#################################
DIR=$(shell pwd)
SRC_DIR=$(DIR)/src
LIB_DIR=-L $(DIR)/../libs/lib/ -lpthread -lcrypto -lssl -lstdc++ -lrt
BIN_DIR=$(DIR)/bin
INCLUDES= -I $(DIR)/src/includes -I /usr/local/ssl/include -I /home/wosign/work/openssl-1.0.1h/include
BIN_NAME=ocsp-client

#############################################


###################OBJ文件及路径############################################
EXT=cpp
SRCS=$(wildcard $(SRC_DIR)/*.$(EXT))


OBJS=$(SRCS:.cpp=.o)
###################编译选项及编译器###################################
CC=gcc
#CFLAGS=-Wall -m64 -W -g -D_LINUX  -fPIC -finput-charset=gb2312
CFLAGS=-Wall -m64 -W -g -O2 -fPIC -D NDEBUG
LDFLAGS=-shared -fPIC


################### 编译目标 ###########################################
### #@echo $ (DEPS_DIR)
.PHONY: all clean rebuild
all:$(OBJS) 
	$(CC) -o $(BIN_DIR)/$(BIN_NAME) $(OBJS) $(CFLAGS) $(LIB_DIR) $(INCLUDES)


$(OBJS):%.o:%.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c  $< -o $@


rebuild: clean all

clean:
	rm -rf $(OBJS) $(BIN_DIR)/$(BIN_NAME)


