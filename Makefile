CC      ?= gcc
CFLAGS  ?= -Wall -Wno-deprecated-declarations
LDLIBS  ?= -lcrypto
SRCS    := src/main.c src/rsa_test.c src/weak_hash_cipher_test.c
OBJS    := $(SRCS:.c=.o)

all: c-lang-test

c-lang-test: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) c-lang-test
