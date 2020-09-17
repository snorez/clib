ARCH=$(shell getconf LONG_BIT)
CLIB_PATH=..
CLIB_INC=$(CLIB_PATH)/include
CLIB_LIB=$(CLIB_PATH)/lib
CLIB_SO=clib$(ARCH)

CC=gcc
CC_FLAGS=
CC_FLAGS+=-g
CC_FLAGS+=-Wall
CC_FLAGS+=-rdynamic
CC_FLAGS+=-DHAVE_CLIB_DBG_FUNC
CC_INCLUDE=

CC_SRCS=\
	testsuite.c \
	test-slist.c \
	test-int-extend.c \
	test-compare-bits.c

CC_OBJS=$(CC_SRCS:%.c=%.o)

EXEC_OBJ = testsuite

all: $(EXEC_OBJ)

$(EXEC_OBJ): $(CC_OBJS)
	$(CC) $(CC_FLAGS) $(CC_OBJS) -L$(CLIB_LIB) -l$(CLIB_SO) -o $@ -Wl,-rpath $(CLIB_LIB)

$(CC_OBJS): %.o: %.c
	$(CC) $(CC_FLAGS) -I$(CLIB_INC) -c -o $@ $<

clean:
	@rm -vf $(CC_OBJS)

distclean: clean
	@rm -vf $(EXEC_OBJ)
