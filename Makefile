CFLAGS += -g -O2 -m64 -std=c99 -pedantic \
	-Wall -Wshadow -Wpointer-arith -Wcast-qual -Wformat -Wformat-security \
	-Werror=format-security -Wstrict-prototypes -Wmissing-prototypes \
	-D_FORTIFY_SOURCE=2 -fPIC -fno-strict-overflow
SRCS = hazmat.c randombytes.c sss.c tweetnacl.c \
    slip39_wordlist.c slip39_mnemonics.c slip39_rs1024.c \
    slip39_encrypt.c slip39_shamir.c \
	hmac.c memzero.c pbkdf2.c sha2.c
OBJS := ${SRCS:.c=.o}

ifeq ($(shell uname -s), Darwin)
LINK := $(shell which libtool) -static -a -o
else
LINK := $(AR) -rcs
endif

all: libsss.a libslip39.a

libsss.a: randombytes/librandombytes.a $(OBJS)
	$(LINK) libsss.a $^

randombytes/librandombytes.a:
	@if [ ! -f randombytes/Makefile ]; then \
		echo "Missing randombytes, use git clone --recursive" >&2 ; \
		exit 1 ; \
	fi
	$(MAKE) -C randombytes librandombytes.a

# Force unrolling loops on hazmat.c
hazmat.o: CFLAGS += -funroll-loops

%.out: %.o randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_hazmat.out: $(OBJS)
test_sss.out: $(OBJS)


libslip39.so: libslip39.a
	$(CC) -shared $(CFLAGS) $^ -o $@

libslip39.a: randombytes/librandombytes.a $(OBJS)
	$(LINK) $@ $^

slip39_tests.c: vectors_to_tests.js vectors.json
	node vectors_to_tests.js > slip39_tests.c

slip39_tests.o: slip39_tests.c

slip39_tests.out: slip39_tests.o hazmat.o slip39_wordlist.o slip39_rs1024.o \
     slip39_shamir.o slip39_mnemonics.o test_random.o slip39_encrypt.o \
     randombytes/librandombytes.a hmac.o memzero.o pbkdf2.o sha2.o
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^
	$(MEMCHECK) ./$@

test_interpolate.o: test_interpolate.c

test_interpolate.out: hazmat.o test_interpolate.o randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_slip39_wordlist.o: slip39.h test_slip39_wordlist.c

slip39_wordlist.o: slip39.h slip39_wordlist.c slip39_wordlist_english.h

test_slip39_wordlist.out: test_slip39_wordlist.o slip39_wordlist.o randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@


test_slip39_buffer.o: slip39.h test_slip39_buffer.c

test_slip39_buffer.out: test_slip39_buffer.o slip39_buffer.o randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_random.o: test_random.c

test_slip39_shamir.o: test_slip39_shamir.c slip39.h

slip39_shamir.o: slip39_shamir.c slip39.h

test_slip39_shamir.out: test_slip39_shamir.o slip39_shamir.o hazmat.o test_random.o hmac.o memzero.o pbkdf2.o sha2.o
	gcc $^ -o $@
	./$@

slip39_encrypt.o: slip39_encrypt.c slip39.h

test_slip39_encrypt.out: test_slip39_encrypt.o slip39_encrypt.o randombytes/librandombytes.a hmac.o memzero.o pbkdf2.o sha2.o
	gcc $^ -o $@
	./$@


test_generate_combine.o: test_generate_combine.c

test_generate_combine.out: test_generate_combine.o hazmat.o slip39_wordlist.o \
     slip39_rs1024.o slip39_shamir.o slip39_mnemonics.o slip39_encrypt.o randombytes/librandombytes.a hmac.o memzero.o pbkdf2.o sha2.o
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

slip39: slip39_cli.c libslip39.a randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)

.PHONY: check
check: test_hazmat.out test_sss.out \
    test_interpolate.out test_slip39_wordlist.out \
    test_slip39_buffer.out \
    test_slip39_shamir.out test_slip39_encrypt.out test_generate_combine.out slip39_tests.out

.PHONY: check check_slip39

.PHONY: clean
clean:
	$(MAKE) -C randombytes $@
	$(RM) *.o *.gch *.a *.out slip39 slip39_tests.c

