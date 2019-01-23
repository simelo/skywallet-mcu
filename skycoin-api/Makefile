CC       ?= gcc

OPTFLAGS ?= -O3 -g -fPIC

CFLAGS   += $(OPTFLAGS) \
            -std=gnu99 \
            -W \
            -Wall \
            -Wextra \
            -Wimplicit-function-declaration \
            -Wredundant-decls \
            -Wstrict-prototypes \
            -Wundef \
            -Wshadow \
            -Wpointer-arith \
            -Wformat \
            -Wreturn-type \
            -Wsign-compare \
            -Wmultichar \
            -Wformat-nonliteral \
            -Winit-self \
            -Wuninitialized \
            -Wformat-security \
            -Werror

ifneq ($(CHECK_PATH),)
ifeq ($(UNAME_S), Linux)
	TESTINC+=-isystem $(CHECK_PATH)/src
	TESTINC+=-isystem $(CHECK_PATH)
endif
ifeq ($(UNAME_S), Darwin)
	TESTINC+=-isystem $(CHECK_PATH)/include
endif
endif

INC=-Itools/
CFLAGS += -I. $(INC)

SRCS += skycoin_crypto.c
SRCS += skycoin_check_signature.c
SRCS += skycoin_check_signature_tools.c
SRCS += $(shell ls tools/*.c)

OBJS   = $(SRCS:.c=.o)

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

LIBS = -L/usr/local/lib/ -lm -lrt
TESTLIBS = -L$(CHECK_PATH)/src -lcheck 

all: test_skycoin_crypto

libskycoin-crypto.so: skycoin_crypto.o $(OBJS)
	$(CC) -rdynamic -shared $(CFLAGS) $(OBJS) -o libskycoin-crypto.so

libskycoin-crypto.a: skycoin_crypto.o $(OBJS)
	$(AR) rcs libskycoin-crypto.a skycoin_crypto.o $(OBJS)

test_skycoin_crypto.o: test_skycoin_crypto.c
	$(CC) $(CFLAGS) $(TESTINC) -o $@ -c $<

test_skycoin_crypto: test_skycoin_crypto.o libskycoin-crypto.so
	$(CC) test_skycoin_crypto.o $(OBJS) -L. -lskycoin-crypto $(LIBS) $(TESTLIBS) -o test_skycoin_crypto



clean:
	rm -f *.o test_skycoin_crypto
	rm -f *.so
	rm -f tools/*.o
	rm -f trezor-tools/*.o
	rm -f *.a
