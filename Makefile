# this is a C program project
# we need to compile it with gcc, and provide some libraries and header files
# however, we should also make it compatible with g++
#
# dependencies:
# 	libcapstone
# 	readline
#
ARCH = 64
# use make with ARCH=32/64
TMP = /tmp
LIB = ./lib
INC = ./include
ARCH = $(shell getconf LONG_BIT)
CWD = $(shell pwd)
vpath %.c ./src/
vpath %.h ./include/

CC = gcc -Wall -std=gnu11 -m$(ARCH) -D_FILE_OFFSET_BITS=64 -g
CC_OPT_static = $(CC) -O2 -DHAS_CAPSTONE
CC_OPT_dynamic = $(CC) -O2 -rdynamic -DHAS_CAPSTONE
CC_OPT_low = $(CC) -O2 -rdynamic

obj_static = clib_error.o clib_file.o clib_list.o clib_string.o clib_net.o \
	     clib_crypt.o clib_elf.o clib_utils.o clib_signal.o clib_dbg.o \
	     clib_disas.o clib_logfile.o clib_plugin.o clib_rbtree.o \
	     clib_cmd_auto_completion.o
obj_dynamic = clib_error.0 clib_file.0 clib_list.0 clib_string.0 clib_net.0 \
	      clib_crypt.0 clib_elf.0 clib_utils.0 clib_signal.0 clib_dbg.0 \
	      clib_disas.0 clib_logfile.0 clib_plugin.0 clib_rbtree.0 \
	      clib_cmd_auto_completion.0
obj_dynamic_low = clib_error.1 clib_file.1 clib_list.1 clib_string.1 clib_net.1 \
		  clib_crypt.1 clib_elf.1 clib_utils.1 clib_signal.1 clib_dbg.1 \
		  clib_disas.1 clib_logfile.1 clib_memcpy.1 clib_plugin.1 \
		  clib_rbtree.1 \
		  clib_cmd_auto_completion.1

all: static shared shared_low_ver

$(obj_static): %.o : %.c %.h
	$(CC_OPT_static) -c $< -o $(TMP)/$@
$(obj_dynamic): %.0 : %.c %.h
	$(CC_OPT_dynamic) -c -fPIC $< -o $(TMP)/$@
$(obj_dynamic_low): %.1 : %.c
	$(CC_OPT_low) -c -fPIC $< -o $(TMP)/$@


static: $(obj_static)
ifeq ($(ARCH),64)
	cd $(TMP);rm -rf clib_static;mkdir clib_static;cd clib_static;ar x /usr/lib/x86_64-linux-gnu/libdl.a;ar x /usr/lib64/libcapstone.a;ar x /usr/lib/x86_64-linux-gnu/libreadline.a;cd ..;ar -rcs libclib64.a $(obj_static_64) $(TMP)/clib_static/*.o;cd $(CWD);cp $(TMP)/libclib64.a $(LIB)/
else
	cd $(TMP);rm -rf clib_static;mkdir clib_static;cd clib_static;ar x /usr/lib32/libdl.a;ar x /usr/lib32/libcapstone.a;ar x /usr/lib/i386-linux-gnu/libreadline.a;cd ..;ar -rcs libclib32.a $(obj_static_32) $(TMP)/clib_static/*.o;cd $(CWD);cp $(TMP)/libclib32.a $(LIB)/
endif

shared: $(obj_dynamic)
	cd $(TMP);$(CC_OPT_dynamic) -rdynamic -shared -fPIC $(obj_dynamic) -lpthread -ldl -lcapstone -lreadline -o libclib$(ARCH).so;cd $(CWD);cp $(TMP)/libclib$(ARCH).so $(LIB)/

shared_low_ver: $(obj_dynamic_low)
	cd $(TMP);$(CC_OPT_low) $(obj_dynamic_low) -Wl,--wrap=memcpy -rdynamic -shared -fPIC -ldl -lpthread -o libclib$(ARCH)_low.so;cd $(CWD);cp $(TMP)/libclib$(ARCH)_low.so $(LIB)/

clean:
	rm -vf $(TMP)/*.o
	rm -vf $(TMP)/*.0
	rm -vf $(TMP)/*.1
	rm -vf $(TMP)/libclib*
	rm -v -rf $(TMP)/clib_static

dist_clean: clean
	rm -vf ./lib/libclib*
