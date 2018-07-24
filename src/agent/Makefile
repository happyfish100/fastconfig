.SUFFIXES: .c .o

COMPILE = $(CC)  -Wall -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -g -O2 -DDEBUG_FLAG
INC_PATH = -I.. -I/usr/local/include
LIB_PATH =  -lfastcommon -lserverframe
TARGET_PATH = /usr/bin
CONFIG_PATH = $(TARGET_CONF_PATH)

ALL_OBJS = ../common/fcfg_proto.o fcfg_agent_func.o fcfg_agent_handler.o fcfg_agent_global.o \
           fcfg_agent_dao.o

ALL_PRGS = config_agentd

all: $(ALL_PRGS)

$(ALL_PRGS): $(ALL_OBJS)

.o:
	$(COMPILE) -o $@ $<  $(LIB_PATH) $(INC_PATH)
.c:
	$(COMPILE) -o $@ $<  $(ALL_OBJS) $(LIB_PATH) $(INC_PATH)
.c.o:
	$(COMPILE) -c -o $@ $<  $(INC_PATH)

install:
	mkdir -p $(TARGET_PATH)
	cp -f $(ALL_PRGS) $(TARGET_PATH)
clean:
	rm -f *.o $(ALL_OBJS) $(ALL_PRGS)