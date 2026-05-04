CC			= gcc
CPPFLAGS	= -Isrc -I$(LIBSODIUM_BUILD)/include -DNDEBUG -D_GNU_SOURCE
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

$(OUT): $(OBJS) $(LIBSODIUM_LIB)
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	strip $@

build/%.o: src/%.c | build
	mkdir -p build/
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

libsodium: $(LIBSODIUM_LIB)

$(LIBSODIUM_LIB): build
	mkdir -p $(LIBSODIUM_BUILD)
	cd $(LIBSODIUM_DIR) && \
		./configure \
			--disable-shared \
			--enable-static \
			--prefix=$(abspath $(LIBSODIUM_BUILD)) && \
		make -j && \
		make install

build:
	mkdir -p build/

clean:
	rm -rf build/
	cd $(LIBSODIUM_DIR) && make clean-recursive || true

.PHONY: all clean libsodium

