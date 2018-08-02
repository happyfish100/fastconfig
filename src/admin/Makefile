.SUFFIXES: .c .lo

TARGET_PATH=/usr/local/bin
CONFIG_PATH=/usr/local/etc

COMPILE = $(CC) -O0 -Wall -D_FILE_OFFSET_BITS=64 -g
INC_PATH = -I.. -I/usr/local/include
LIB_PATH = -L/usr/local/lib -lfastcommon -lpthread

SHARED_OBJS = ../common/fcfg_proto.lo fcfg_admin_func.lo
ADMIN_SHARED_OBJS = fcfg_admin_set_config.lo fcfg_admin_get_config.lo \
                    fcfg_admin_del_config.lo fcfg_admin_list_config.lo \
                    fcfg_admin_add_env.lo fcfg_admin_del_env.lo \
                    fcfg_admin_get_env.lo fcfg_admin_list_env.lo
ALL_OBJS = $(SHARED_OBJS) $(ADMIN_SHARED_OBJS)

ALL_HEADERS = fcfg_admin.h
ALL_PRGS =
SHARED_LIBS = libfcfgadmin.so
ALL_LIBS = $(SHARED_LIBS)

all: $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS)
libfcfgadmin.so:
	$(COMPILE) -o $@ $< -shared $(ALL_OBJS) $(LIB_PATH)
.c:
	$(COMPILE) -o $@ $< $(ALL_OBJS) $(LIB_PATH) $(INC_PATH)
.c.lo:
	$(COMPILE) -c -fPIC -o $@ $<  $(INC_PATH)
install:
	mkdir -p $(DESTDIR)/usr/local/lib
	mkdir -p $(DESTDIR)/usr/lib
	install -m 755 $(SHARED_LIBS) $(DESTDIR)/usr/local/lib
	cp -f $(ALL_HEADERS) /usr/local/include
clean:
	rm -f $(ALL_OBJS) $(ALL_PRGS) $(ALL_LIBS)
