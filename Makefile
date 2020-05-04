# this is a C program project
# we need to compile it with gcc, and provide some libraries and header files
# however, we should also make it compatible with g++
#
# dependencies:
# 	libcapstone
# 	readline
# 	ncurses
#
ARCH = 64
# use make with ARCH=32/64
TMP = /tmp/clib_make
LIB = ./lib
INC = ./include
ARCH = $(shell getconf LONG_BIT)
CWD = $(shell pwd)
CAPSTONE_ALIB64=/usr/lib
CAPSTONE_ALIB32=/usr/lib32
vpath %.c ./src/
vpath %.h ./include/
vpath %.o $(TMP)/
vpath %.0 $(TMP)/
vpath %.1 $(TMP)/

CC = gcc
SELF_CFLAGS+=-g -O3
SELF_CFLAGS+=-Wall -std=gnu11 -m$(ARCH) -D_FILE_OFFSET_BITS=64
#SELF_CFLAGS+=-fno-omit-frame-pointer
#SELF_CFLAGS+=-DCONFIG_CLIB_THREADPOOL_MAX=0x40
#SELF_CFLAGS+=-DCONFIG_CLIB_THREAD_ARG_MAX=0x10
#SELF_CFLAGS+=-DCONFIG_CLIB_MM_DESC_LEN=8
#SELF_CFLAGS+=-DCONFIG_CLIB_MM_MMAP_BLKSZ=32*1024*1024
#SELF_CFLAGS+=-DCONFIG_SOCK_BUF_LEN_ORIG=128*1024
SELF_CFLAGS+=-DCONFIG_CLIB_UI_MAX_DEPTH=8
#SELF_CFLAGS+=-DCONFIG_OBJPOOL_MAX=0x100000
#SELF_CFLAGS+=-DCONFIG_OBJPOOL_DEF=0x10000
#SELF_CFLAGS+=-DCONFIG_CALL_FUNC_MAX_ARGS=9
#SELF_CFLAGS+=-DCONFIG_CLIB_MT_PRINT_LINE_LEN=512
#SELF_CFLAGS+=-DCONFIG_IO_BYTES=512*1024*1024
#SELF_CFLAGS+=-DCONFIG_COPY_BLKSZ=256*1024*1024
#SELF_CFLAGS+=-DCONFIG_USLEEP_TIME=3000
#SELF_CFLAGS+=-DCONFIG_LOOP_MORE_TIMES=1
#SELF_CFLAGS+=-DCONFIG_TAB_BYTES=8
SELF_CFLAGS+=-DCONFIG_BT_DEPTH=8
CC_FLAGS=$(SELF_CFLAGS) $(EXTRA_CFLAGS)
CC_OPT_static = $(CC) $(CC_FLAGS) -rdynamic -DHAS_CAPSTONE
CC_OPT_dynamic = $(CC) $(CC_FLAGS) -rdynamic -DHAS_CAPSTONE
CC_OPT_low = $(CC) $(CC_FLAGS) -rdynamic

obj_static = clib_eh.o clib_file.o clib_list.o clib_buf.o clib_net.o \
	     clib_crypt.o clib_elf.o clib_utils.o clib_timer.o \
	     clib_disas.o clib_logfile.o clib_module.o clib_rbtree.o \
	     clib_ui.o clib_mm.o clib_print.o clib_rwpool.o clib_threadpool.o
obj_dynamic = clib_eh.0 clib_file.0 clib_list.0 clib_buf.0 clib_net.0 \
	      clib_crypt.0 clib_elf.0 clib_utils.0 clib_timer.0 \
	      clib_disas.0 clib_logfile.0 clib_module.0 clib_rbtree.0 \
	      clib_ui.0 clib_mm.0 clib_print.0 clib_rwpool.0 clib_threadpool.0
obj_dynamic_low = clib_eh.1 clib_file.1 clib_list.1 clib_buf.1 clib_net.1 \
		  clib_crypt.1 clib_elf.1 clib_utils.1 clib_timer.1 \
		  clib_disas.1 clib_logfile.1 clib_memcpy.1 clib_module.1 \
		  clib_rbtree.1 \
		  clib_ui.1 clib_mm.1 clib_print.1 clib_rwpool.1 clib_threadpool.1

# all: static shared shared_low_ver
all: prepare shared

prepare:
	@mkdir -p $(TMP)

$(obj_static): %.o : %.c %.h
	$(CC_OPT_static) -c $< -o $(TMP)/$@
$(obj_dynamic): %.0 : %.c %.h
	$(CC_OPT_dynamic) -c -fPIC $< -o $(TMP)/$@
$(obj_dynamic_low): %.1 : %.c
	$(CC_OPT_low) -c -fPIC $< -o $(TMP)/$@


static: $(obj_static)
ifeq ($(ARCH),64)
	cd $(TMP);rm -rf clib_static;mkdir clib_static;cd clib_static;ar x $(CAPSTONE_ALIB64)/x86_64-linux-gnu/libdl.a;ar x $(CAPSTONE_ALIB64)/libcapstone.a;ar x $(CAPSTONE_ALIB64)/x86_64-linux-gnu/libreadline.a;cd ..;ar -rcs libclib64.a $(obj_static_64) $(TMP)/clib_static/*.o;cd $(CWD);cp $(TMP)/libclib64.a $(LIB)/
else
	cd $(TMP);rm -rf clib_static;mkdir clib_static;cd clib_static;ar x $(CAPSTONE_ALIB32)/libdl.a;ar x $(CAPSTONE_ALIB32)/libcapstone.a;ar x $(CAPSTONE_ALIB32)/i386-linux-gnu/libreadline.a;cd ..;ar -rcs libclib32.a $(obj_static_32) $(TMP)/clib_static/*.o;cd $(CWD);cp $(TMP)/libclib32.a $(LIB)/
endif

# before copy, we need to use rm to delete the file first, then do the copy
# otherwise, program load this lib will crash
shared: $(obj_dynamic)
	cd $(TMP);$(CC_OPT_dynamic) -rdynamic -shared -fPIC $(obj_dynamic) -lpthread -ldl -lcapstone -lreadline -lncurses -o libclib$(ARCH).so;cd $(CWD);rm -f $(LIB)/libclib$(ARCH).so;cp $(TMP)/libclib$(ARCH).so $(LIB)/

shared_low_ver: $(obj_dynamic_low)
	cd $(TMP);$(CC_OPT_low) $(obj_dynamic_low) -Wl,--wrap=memcpy -rdynamic -shared -fPIC -ldl -lpthread -o libclib$(ARCH)_low.so;cd $(CWD);rm -f $(LIB)/libclib$(ARCH)_low.so;cp $(TMP)/libclib$(ARCH)_low.so $(LIB)/

clean:
	@rm -vf $(TMP)/*.o
	@rm -vf $(TMP)/*.0
	@rm -vf $(TMP)/*.1
	@rm -vf $(TMP)/libclib*
	@rm -v -rf $(TMP)/clib_static

dist_clean: clean
	@rm -vf ./lib/libclib*
