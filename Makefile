
# CC		= m68k-next-nextstep3-gcc
CC		= i386-next-nextstep3-gcc

# Where to find openssl distribution

SSL_DIR=/me/openssl-1.0.2l.dirty

# Flags to pass to compiler

DEBUG_LEVEL	= -g -DNDEBUG=1
EXTRA_CFLAGS	= -Wformat -Wshadow -Wmissing-prototypes -Wmissing-declarations -Werror
CFLAGS		= $(DEBUG_LEVEL) $(EXTRA_CFLAGS)

# Flags to pass to C pre-processor

CPPFLAGS	= -I$(SSL_DIR)/include

# Flags to pass to linker.

LDFLAGS		= -L$(SSL_DIR)

# Libraries to link with.

LDLIBS		= -lcrypto $(SSL_DIR)/getattr.o

PROGS 		= t-rsa t-hmac
OBJS		= t-rsa.o t-hmac.o

.PHONY: all

all: $(PROGS)

$(OBJS):
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

$(PROGS): $(OBJS)

clean:
	rm -f ${PROGS}
