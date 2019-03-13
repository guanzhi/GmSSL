SRC=$(wildcard *.c) $(wildcard primitives/*.c)
OBJ=$(patsubst %.c, %.o, $(SRC))

CFLAGS_COMMON=-std=c89 -pedantic -Wall -Wextra -Wno-long-long -march=native
LDFLAGS=-lcrypto

VERSION_S= -DPORS_k=24 -DMERKLE_h=5  -DGRAVITY_d=1  -DGRAVITY_c=10
VERSION_M= -DPORS_k=32 -DMERKLE_h=5  -DGRAVITY_d=7  -DGRAVITY_c=15
VERSION_L= -DPORS_k=28 -DMERKLE_h=5  -DGRAVITY_d=10 -DGRAVITY_c=14

VERSION=$(VERSION_S)

CFLAGS_COMMON+=$(VERSION)
CFLAGS=$(CFLAGS_COMMON) -O3 -fomit-frame-pointer
CFLAGS_SANITIZED=$(CFLAGS_COMMON) -fsanitize=address,undefined -g

KERNEL_NAME := $(shell uname -s)
ifeq ($(KERNEL_NAME), Darwin)
	CFLAGS += -I/usr/local/opt/openssl/include
	LDFLAGS += -L/usr/local/opt/openssl/lib
endif

all: help

help:
			@echo "Please choose a target:"
			@echo "\tanalyze\t\t runs static analyzers"
			@echo "\tbench\t\t runs speed benchmarks"
			@echo "\tclean\t\t cleans up"
			@echo "\tformat\t\t formats the code using .clang-format rules"

bench:		$(SRC)
			$(CC) $(CFLAGS) $(LDFLAGS) $^ -o bench
			./bench

format:
			clang-format -i *.c *.h

analyze:
			cppcheck . --std=c89
			scan-build gcc -c $(CFLAGS_SANITIZED) *.c
			cppclean .
			rm -f *.o

cloc:
			cloc $(wildcard *.c) $(wildcard *.h)

clean:
			rm -f bench *.dSYM *.o

.PHONY: clean format analyze cloc bench

