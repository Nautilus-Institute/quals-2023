### This Makefile was written for GNU Make. ###
ifeq ($(OPT),true)
	COPTFLAGS  := -flto -Ofast -mtune=native -march=native -DNDEBUG
	LDOPTFLAGS := -flto -Ofast -s
else
ifeq ($(DEBUG),true)
	COPTFLAGS  := -O0 -g3 -ftrapv -fstack-protector-all -D_FORTIFY_SOURCE=2
	LDLIBS     := -lssp
else
	COPTFLAGS  := -O3 -DNDEBUG
	LDOPTFLAGS := -O3 -s
endif
endif
C_WARNING_FLAGS := -Wall -Wextra -Wformat=2 -Wstrict-aliasing=2 \
                   -Wcast-align -Wcast-qual -Wconversion \
                   -Wfloat-equal -Wpointer-arith -Wswitch-enum \
                   -Wwrite-strings -pedantic
MAX_SOURCE_SIZE   ?= 65536
MAX_BYTECODE_SIZE ?= 1048576
MAX_LABEL_LENGTH  ?= 65536
MAX_N_LABEL       ?= 1024
UNDEF_LIST_SIZE   ?= 256
STACK_SIZE        ?= 65536
HEAP_SIZE         ?= 65536
CALL_STACK_SIZE   ?= 65536
WS_INT            ?= int
WS_ADDR_INT       ?= 'unsigned int'
INDENT_STR        ?= '"  "'
MACROS ?= -DMAX_SOURCE_SIZE=$(MAX_SOURCE_SIZE) \
          -DMAX_BYTECODE_SIZE=$(MAX_BYTECODE_SIZE) \
          -DMAX_LABEL_LENGTH=$(MAX_LABEL_LENGTH) \
          -DMAX_N_LABEL=$(MAX_N_LABEL) \
          -DUNDEF_LIST_SIZE=$(UNDEF_LIST_SIZE) \
          -DSTACK_SIZE=$(STACK_SIZE) \
          -DHEAP_SIZE=$(HEAP_SIZE) \
          -DCALL_STACK_SIZE=$(CALL_STACK_SIZE) \
          -DWS_INT=$(WS_INT) \
          -DWS_ADDR_INT=$(WS_ADDR_INT) \
          -DINDENT_STR=$(INDENT_STR)

CC      := gcc
CFLAGS  := -pipe $(C_WARNING_FLAGS) $(COPTFLAGS) $(MACROS)
LDFLAGS := -pipe $(LDOPTFLAGS)
TARGET  := whitespace
OBJ     := $(addsuffix .o, $(basename $(TARGET)))
SRC     := $(OBJ:%.o=%.c)

ifeq ($(OS),Windows_NT)
    TARGET := $(addsuffix .exe, $(TARGET))
else
    TARGET := $(addsuffix .out, $(TARGET))
endif


%.exe:
	$(CC) $(LDFLAGS) $(filter %.c %.o, $^) $(LDLIBS) -o $@
%.out:
	$(CC) $(LDFLAGS) $(filter %.c %.o, $^) $(LDLIBS) -o $@


.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJ)

$(OBJ): $(SRC)


.PHONY: test
test:
	./$(TARGET) -h


.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJ)
.PHONY: cleanobj
cleanobj:
	$(RM) $(OBJ)
