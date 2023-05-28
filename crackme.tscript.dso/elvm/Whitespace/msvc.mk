### This Makefile was written for nmake. ###
GETOPT_DIR        = getopt
GETOPT_REPOSITORY = https://github.com/koturn/$(GETOPT_DIR).git
GETOPT_LIBS_DIR   = $(GETOPT_DIR)/lib
GETOPT_LIB        = getopt$(DBG_SUFFIX).lib
GETOPT_LDLIBS     = /LIBPATH:$(GETOPT_LIBS_DIR) $(GETOPT_LIB)
GETOPT_INCS       = /Igetopt/include/

!if "$(CRTDLL)" == "true"
CRTLIB = /MD$(DBG_SUFFIX)
!else
CRTLIB = /MT$(DBG_SUFFIX)
!endif

!if "$(DEBUG)" == "true"
MSVCDBG_DIR        = msvcdbg
MSVCDBG_REPOSITORY = https://github.com/koturn/$(MSVCDBG_DIR).git
MSVCDBG_INCS       = /Imsvcdbg/

DBG_SUFFIX  = d
COPTFLAGS   = /Od /GS /Zi $(CRTLIB)
LDOPTFLAGS  = /Od /GS /Zi $(CRTLIB)
MSVC_MACROS = /D_CRTDBG_MAP_ALLOC /D_USE_MATH_DEFINES
!else
DBG_SUFFIX  =
COPTFLAGS   = /Ox /GL $(CRTLIB)
LDOPTFLAGS  = /Ox /GL $(CRTLIB)
MSVC_MACROS = /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_WARNINGS \
              /D_USE_MATH_DEFINES
!endif

MAX_SOURCE_SIZE   = 65536
MAX_BYTECODE_SIZE = 1048576
MAX_LABEL_LENGTH  = 65536
MAX_N_LABEL       = 1024
UNDEF_LIST_SIZE   = 256
STACK_SIZE        = 65536
HEAP_SIZE         = 65536
CALL_STACK_SIZE   = 65536
WS_INT            = int
WS_ADDR_INT       = "unsigned int"
INDENT_STR        = "\"  \""

MACROS = $(MSVC_MACROS) \
         /DMAX_SOURCE_SIZE=$(MAX_SOURCE_SIZE) \
         /DMAX_BYTECODE_SIZE=$(MAX_BYTECODE_SIZE) \
         /DMAX_LABEL_LENGTH=$(MAX_LABEL_LENGTH) \
         /DMAX_N_LABEL=$(MAX_N_LABEL) \
         /DUNDEF_LIST_SIZE=$(UNDEF_LIST_SIZE) \
         /DSTACK_SIZE=$(STACK_SIZE) \
         /DHEAP_SIZE=$(HEAP_SIZE) \
         /DCALL_STACK_SIZE=$(CALL_STACK_SIZE) \
         /DWS_INT=$(WS_INT) \
         /DWS_ADDR_INT=$(WS_ADDR_INT) \
         /DINDENT_STR=$(INDENT_STR)

CC       = cl
RM       = del /F
MAKE     = $(MAKE) /nologo
GIT      = git
INCS     = $(GETOPT_INCS) $(MSVCDBG_INCS)
CFLAGS   = /nologo $(COPTFLAGS) /W4 /c $(INCS) $(MACROS)
LDFLAGS  = /nologo $(LDOPTFLAGS)
LDLIBS   = /link $(GETOPT_LDLIBS)
TARGET   = whitespace.exe
OBJ      = $(TARGET:.exe=.obj)
SRC      = $(TARGET:.exe=.c)
MAKEFILE = msvc.mk


.SUFFIXES: .c .obj .exe
.obj.exe:
	$(CC) $(LDFLAGS) $** /Fe$@ $(LDLIBS)
.c.obj:
	$(CC) $(CFLAGS) $** /Fo$@


all: $(GETOPT_LIBS_DIR)/$(GETOPT_LIB) $(MSVCDBG_DIR)/NUL $(TARGET)

$(TARGET): $(OBJ)

$(OBJ): $(SRC)

$(GETOPT_LIBS_DIR)/$(GETOPT_LIB):
	@if not exist $(@D)/NUL \
		$(GIT) clone $(GETOPT_REPOSITORY)
	cd $(GETOPT_DIR)  &  $(MAKE) /f $(MAKEFILE)  &  cd $(MAKEDIR)

$(MSVCDBG_DIR)/NUL:
	@if not exist $(@D)/NUL \
		$(GIT) clone $(MSVCDBG_REPOSITORY)


test:
	$(TARGET) -h


clean:
	$(RM) $(TARGET) $(OBJ)
cleanobj:
	$(RM) $(OBJ)
