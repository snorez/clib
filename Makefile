TMP = /tmp
LIB = ./lib
INC = ./include
ARCH = $(shell getconf LONG_BIT)
#ARCH = 32
CWD = $(shell pwd)
vpath %.c ./src/
vpath %.c ./src/file-format/
vpath %.h ./include/

CC = gcc -Wall -std=gnu11 -m$(ARCH) -D_FILE_OFFSET_BITS=64 -g
CC_OPT_static = $(CC) -O2 -DHAS_CAPSTONE
CC_OPT_dynamic = $(CC) -O2 -rdynamic -DHAS_CAPSTONE
CC_OPT_low = $(CC) -O2 -rdynamic

obj_static = error.o file.o list.o string.o net.o crypt.o elf.o \
	 utils.o signal.o dbg.o disas.o log.o plugin.o class.o
obj_dynamic = error.0 file.0 list.0 string.0 net.0 crypt.0 elf.0 \
	 utils.0 signal.0 dbg.0 disas.0 log.0 plugin.0 class.0
obj_dynamic_low = error.1 file.1 list.1 string.1 net.1 crypt.1 elf.1 \
	 utils.1 signal.1 dbg.1 disas.1 log.1 memcpy.1 plugin.1 class.1

all: static shared shared_low_ver

$(obj_static): %.o : %.c %.h
	$(CC_OPT_static) -c $< -o $(TMP)/$@
$(obj_dynamic): %.0 : %.c %.h
	$(CC_OPT_dynamic) -c -fPIC $< -o $(TMP)/$@
$(obj_dynamic_low): %.1 : %.c
	$(CC_OPT_low) -c -fPIC $< -o $(TMP)/$@


static: $(obj_static)
ifeq ($(ARCH),64)
	cd $(TMP);rm -rf zerons_static;mkdir zerons_static;cd zerons_static;ar x /usr/lib/x86_64-linux-gnu/libdl.a;ar x /usr/lib64/libcapstone.a;cd ..;ar -rcs libzerons64.a $(obj_static_64) $(TMP)/zerons_static/*.o;cd $(CWD);cp $(TMP)/libzerons64.a $(LIB)/
else
	cd $(TMP);rm -rf zerons_static;mkdir zerons_static;cd zerons_static;ar x /usr/lib32/libdl.a;ar x /usr/lib32/libcapstone.a;cd ..;ar -rcs libzerons32.a $(obj_static_32) $(TMP)/zerons_static/*.o;cd $(CWD);cp $(TMP)/libzerons32.a $(LIB)/
endif

shared: $(obj_dynamic)
	cd $(TMP);$(CC_OPT_dynamic) -rdynamic -shared -fPIC $(obj_dynamic) -lpthread -ldl -lcapstone -o libzerons$(ARCH).so;cd $(CWD);cp $(TMP)/libzerons$(ARCH).so $(LIB)/

shared_low_ver: $(obj_dynamic_low)
	cd $(TMP);$(CC_OPT_low) $(obj_dynamic_low) -Wl,--wrap=memcpy -rdynamic -shared -fPIC -ldl -lpthread -o libzerons$(ARCH)_low.so;cd $(CWD);cp $(TMP)/libzerons$(ARCH)_low.so $(LIB)/

clean:
	rm -vf $(TMP)/*.o
	rm -vf $(TMP)/*.0
	rm -vf $(TMP)/*.1
	rm -vf $(TMP)/libzerons*
	rm -v -rf $(TMP)/zerons_static

dist_clean: clean
	rm -vf ./lib/libzerons*
