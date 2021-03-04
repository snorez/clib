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
SELF_CFLAGS+=-g -O2
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
LK_FLAG=-lpthread -ldl -lcapstone -lreadline -lncurses

SRCS = \
       clib_eh.c \
       clib_file.c \
       clib_list.c \
       clib_buf.c \
       clib_net.c \
       clib_crypt.c \
       clib_elf.c \
       clib_utils.c \
       clib_timer.c \
       clib_disas.c \
       clib_logfile.c \
       clib_module.c \
       clib_rbtree.c \
       clib_ui.c \
       clib_mm.c \
       clib_print.c \
       clib_rwpool.c \
       clib_threadpool.c \
       insn.c \
       inat.c \
       clib_bitmap.c \
       clib_json.c \
       clib_sme.c \
       qemu_fuzzlib.c

obj_static = $(SRCS:%.c=%.o)
obj_dynamic = $(SRCS:%.c=%.0)
obj_dynamic_low = $(SRCS:%.c=%.1)

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
	cd $(TMP);$(CC_OPT_dynamic) -rdynamic -shared -fPIC $(obj_dynamic) $(LK_FLAG) -o libclib$(ARCH).so;cd $(CWD);rm -f $(LIB)/libclib$(ARCH).so;cp $(TMP)/libclib$(ARCH).so $(LIB)/

shared_low_ver: $(obj_dynamic_low)
	cd $(TMP);$(CC_OPT_low) $(obj_dynamic_low) -Wl,--wrap=memcpy -rdynamic -shared -fPIC -ldl -lpthread -o libclib$(ARCH)_low.so;cd $(CWD);rm -f $(LIB)/libclib$(ARCH)_low.so;cp $(TMP)/libclib$(ARCH)_low.so $(LIB)/

clean:
	@rm -vf $(TMP)/*.o
	@rm -vf $(TMP)/*.0
	@rm -vf $(TMP)/*.1
	@rm -vf $(TMP)/libclib*
	@rm -v -rf $(TMP)/clib_static

distclean: clean
	@rm -vf ./lib/libclib*
