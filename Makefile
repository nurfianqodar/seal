CC			:= gcc
CPPFLAGS	:= -Isrc -DNDEBUG
CFLAGS		:= -std=gnu23 -O2 -fsanitize=undefined -fno-omit-frame-pointer -Wall -Wextra
LDFLAGS		:= -static -lsodium

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

