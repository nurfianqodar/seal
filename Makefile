CC			:= gcc
CPPFLAGS	:= -Isrc -DDEBUG
CFLAGS		:= -std=gnu23 -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra
LDFLAGS		:= -lsodium -lc

SRCS		:= $(wildcard src/*.c)
OBJS		:= $(SRCS:src/%.c=build/%.o)

PROGRAM		:= seal
OUT			:= build/$(PROGRAM)


all: $(OUT)

$(OUT): $(OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/%.o: src/%.c
	mkdir -p build/
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build/

.PHONY: all clean

