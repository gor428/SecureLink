CC ?= gcc
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wconversion
LDLIBS += -lcrypto

BUILD := build
LIB_OBJS := $(BUILD)/crypto.o $(BUILD)/checksum.o $(BUILD)/packet.o $(BUILD)/handshake.o

.PHONY: all test clean
all: $(BUILD)/libsecurelink.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/crypto.o: src/crypto.c include/crypto.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/checksum.o: src/checksum.c include/checksum.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/packet.o: src/packet.c include/packet.h include/checksum.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/handshake.o: src/handshake.c include/handshake.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/libsecurelink.a: $(LIB_OBJS)
	ar rcs $@ $^

$(BUILD)/test_crypto: tests/test_crypto.c $(BUILD)/crypto.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/test_handshake: tests/test_handshake.c $(BUILD)/handshake.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

test: $(BUILD)/test_crypto $(BUILD)/test_handshake
	./$(BUILD)/test_crypto
	./$(BUILD)/test_handshake

clean:
	rm -rf $(BUILD)
