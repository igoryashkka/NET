CC = gcc
CFLAGS = -Wall -Wextra -g -I/path/to/openssl/include `pkg-config --cflags gtk+-3.0`
LIBS = -lpcap -lssl -lcrypto `pkg-config --libs gtk+-3.0`
TEST_LIBS = -L. -lacutest

SRC_DIR = src
OBJ_DIR = obj
TEST_DIR = test
GUI_DIR = gui

NET_DIR = network

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
GUI_SRC_FILES = $(wildcard $(GUI_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))
GUI_OBJ_FILES = $(patsubst $(GUI_DIR)/%.c,$(OBJ_DIR)/%.o,$(GUI_SRC_FILES))

NET_SRC_FILES = $(wildcard $(NET_DIR)/*.c)
NET_OBJ_FILES = $(patsubst $(NET_DIR)/%.c,$(OBJ_DIR)/%.o,$(NET_SRC_FILES))

TARGET = run
TEST_TARGET = test_run

all: $(TARGET)

$(TARGET): $(OBJ_FILES) $(GUI_OBJ_FILES) $(NET_OBJ_FILES)| $(OBJ_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) $(GUI_OBJ_FILES) $(NET_OBJ_FILES) -o $(TARGET) $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(GUI_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(NET_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@


debug: CFLAGS += -O0
debug: $(TARGET)

test: $(OBJ_FILES) $(OBJ_DIR)/unit_test.o | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) $(OBJ_DIR)/unit_test.o -o $(TEST_TARGET) $(LIBS) $(TEST_LIBS)
	./$(TEST_TARGET)

$(OBJ_DIR)/unit_test.o: $(TEST_DIR)/unit_test.c $(TEST_DIR)/acutest.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -f $(TARGET) $(TEST_TARGET) *.o
	rm -rf $(OBJ_DIR)

.PHONY: all debug test clean
