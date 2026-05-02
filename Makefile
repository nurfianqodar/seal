CC			= gcc
CPPFLAGS	= -Isrc -DNDEBUG -Ibuild/libsodium/include
CFLAGS		= -std=gnu23 -Os -flto -ffunction-sections -fdata-sections -fno-omit-frame-pointer -Wall -Wextra
LDFLAGS		= $(LIBSODIUM_LIB) -static -flto -Wl,--gc-sections


LIBSODIUM_DIR		= lib/libsodium
LIBSODIUM_BUILD		= build/libsodium
LIBSODIUM_LIB		= $(LIBSODIUM_BUILD)/lib/libsodium.a


SRCS		= $(wildcard src/*.c)
OBJS		= $(SRCS:src/%.c=build/%.o)

PROGRAM		= seal
OUT			= build/$(PROGRAM)


all: $(OUT)

$(OUT): $(OBJS) | $(LIBSODIUM_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/%.o: src/%.c
	mkdir -p build/
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@


$(LIBSODIUM_LIB):
	mkdir -p $(LIBSODIUM_BUILD)
	cd $(LIBSODIUM_DIR) && \
		./configure \
			--disable-shared \
			--enable-static \
			--prefix=$(abspath $(LIBSODIUM_BUILD)) && \
		make -j && \
		make install

clean:
	rm -rf build/

.PHONY: all clean

