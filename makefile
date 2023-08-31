CC = gcc
CFLAGS = -Wall -Wextra -g         # Add -g for debug symbols
LIBS = -lpcap
TEST_LIBS = -L. -lacutest         # Assuming you'll compile Acutest library

SRC_DIR = src
OBJ_DIR = obj
TEST_DIR = test

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

all: run

run: $(OBJ_FILES) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o run $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

debug:                              # New target for building with debug symbols
debug: CFLAGS += -O0
debug: run

test: $(OBJ_FILES) $(OBJ_DIR)/unit_test.o | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) $(OBJ_DIR)/unit_test.o -o test_run $(LIBS) $(TEST_LIBS)
	./test_run

$(OBJ_DIR)/unit_test.o: $(TEST_DIR)/unit_test.c $(TEST_DIR)/acutest.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

clean:
	rm -f run test_run *.o
	rm -rf $(OBJ_DIR)

.PHONY: all debug test clean
