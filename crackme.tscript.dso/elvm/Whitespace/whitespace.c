/*!
 * @file whitespace.c
 * @brief An interpreter and C-translator of Whitespace
 * @author koturn
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>
#if defined(_MSC_VER) && defined(_DEBUG)
#  include <msvcdbg.h>
#endif

#ifndef MAX_SOURCE_SIZE
#  define MAX_SOURCE_SIZE  65536
#endif
#ifndef MAX_BYTECODE_SIZE
#  define MAX_BYTECODE_SIZE  1048576
#endif
#ifndef MAX_LABEL_LENGTH
#  define MAX_LABEL_LENGTH  65536
#endif
#ifndef MAX_N_LABEL
#  define MAX_N_LABEL  1024
#endif
#ifndef UNDEF_LIST_SIZE
#  define UNDEF_LIST_SIZE  256
#endif
#ifndef STACK_SIZE
#  define STACK_SIZE  65536
#endif
#ifndef HEAP_SIZE
#  define HEAP_SIZE  65536
#endif
#ifndef CALL_STACK_SIZE
#  define CALL_STACK_SIZE  65536
#endif
#ifndef WS_INT
#  define WS_INT  int
#endif
#ifndef WS_ADDR_INT
#  define WS_ADDR_INT  unsigned int
#endif
#ifndef INDENT_STR
#  define INDENT_STR  "  "
#endif

#define TRUE  1
#define FALSE 0
#define UNDEF_ADDR  ((WsAddrInt) -1)
#define LENGTHOF(array)  (sizeof(array) / sizeof((array)[0]))
#define ADDR_DIFF(a, b) \
  ((const unsigned char *) (a) - (const unsigned char *) (b))
#define SWAP(type, a, b) \
  do { \
    type __tmp_swap_var__ = *(a); \
    *(a) = *(b); \
    *(b) = __tmp_swap_var__; \
  } while (0)


enum OpCode {
  FLOW_HALT = 0x00,
  STACK_PUSH, STACK_DUP_N, STACK_DUP, STACK_SLIDE, STACK_SWAP, STACK_DISCARD,
  ARITH_ADD, ARITH_SUB, ARITH_MUL, ARITH_DIV, ARITH_MOD,
  HEAP_STORE, HEAP_LOAD,
  FLOW_LABEL, FLOW_GOSUB, FLOW_JUMP, FLOW_BEZ, FLOW_BLTZ, FLOW_ENDSUB,
  IO_PUT_CHAR, IO_PUT_NUM, IO_READ_CHAR, IO_READ_NUM
};


typedef WS_INT  WsInt;
typedef WS_ADDR_INT  WsAddrInt;

typedef struct {
  const char *in_filename;
  const char *out_filename;
  int mode;
} Param;

typedef struct {
  WsAddrInt  addr;
  int        n_undef;
  char      *label;
  WsAddrInt *undef_list;
} LabelInfo;


static void
parse_arguments(Param *param, int argc, char *argv[]);

static void
show_usage(const char *progname);

static int
read_file(FILE *fp, char *code, size_t length);


static void
execute(const unsigned char *bytecode);

static void
compile(unsigned char *bytecode, size_t *bytecode_size, const char *code);

static void
gen_stack_code(unsigned char **bytecode_ptr, const char **code_ptr);

static void
gen_arith_code(unsigned char **bytecode_ptr, const char **code_ptr);

static void
gen_heap_code(unsigned char **bytecode_ptr, const char **code_ptr);

static void
gen_io_code(unsigned char **bytecode_ptr, const char **code_ptr);

static void
gen_flow_code(unsigned char **bytecode_ptr, const char **code_ptr, unsigned char *base);


static void
process_label_define(unsigned char **bytecode_ptr, const char **code_ptr, unsigned char *base);

static void
process_label_jump(unsigned char **bytecode_ptr, const char **code_ptr, unsigned char *base);

static LabelInfo *
search_label(const char *label);

static void
add_label(const char *_label, WsAddrInt addr);

static void
add_undef_label(const char *_label, WsAddrInt pos);

static void
free_label_info_list(LabelInfo *label_info_list[]);


static void
stack_push(WsInt e);

static WsInt
stack_pop(void);

static void
stack_dup_n(size_t n);

static void
stack_slide(size_t n);

static void
stack_swap(void);


static int
read_nstr(const char **code_ptr);

static char *
read_label(const char **code_ptr);


static int
translate(FILE *fp, const char *code);

static void
print_stack_code(FILE *fp, const char **code_ptr);

static void
print_arith_code(FILE *fp, const char **code_ptr);

static void
print_heap_code(FILE *fp, const char **code_ptr);

static void
print_io_code(FILE *fp, const char **code_ptr);

static void
print_flow_code(FILE *fp, const char **code_ptr);

static void
print_code_header(FILE *fp);

static void
print_code_footer(FILE *fp);


static void
show_bytecode(const unsigned char *bytecode, size_t bytecode_size);

static void
show_mnemonic(FILE *fp, const unsigned char *bytecode, size_t bytecode_size);

static void
filter(FILE *fp, const char *code);


static WsInt stack[STACK_SIZE] = {0};
static size_t stack_idx = 0;

static LabelInfo *label_info_list[MAX_N_LABEL] = {NULL};
static size_t n_label_info = 0;




/*!
 * @brief Entry point of thie program
 * @param [in] argc  The number of argument (include this program name)
 * @param [in] argv  The array off argument strings
 * @return  Status-code
 */
int
main(int argc, char *argv[])
{
  static char code[MAX_SOURCE_SIZE] = {0};
  static unsigned char bytecode[MAX_BYTECODE_SIZE] = {0};
  Param param = {NULL, NULL, '*'};
  FILE *ifp, *ofp;
  size_t bytecode_size;

  parse_arguments(&param, argc, argv);
  if (param.in_filename == NULL) {
    fprintf(stderr, "Invalid arguments\n");
    return EXIT_FAILURE;
  }
  if (!strcmp(param.in_filename, "-")) {
    ifp = stdin;
  } else if ((ifp = fopen(param.in_filename, "r")) == NULL) {
    fprintf(stderr, "Unable to open file: %s\n", argv[1]);
    return EXIT_FAILURE;
  }
  if (!read_file(ifp, code, LENGTHOF(code))) {
    return EXIT_FAILURE;
  }
  if (ifp != stdin) {
    fclose(ifp);
  }

  switch (param.mode) {
    case 'b':
      compile(bytecode, &bytecode_size, code);
      show_bytecode(bytecode, bytecode_size);
      break;
    case 'f':
      if (param.out_filename == NULL) {
        filter(stdout, code);
      } else {
        if ((ofp = fopen(param.out_filename, "w")) == NULL) {
          fprintf(stderr, "Unable to open file: %s\n", param.out_filename);
          return EXIT_FAILURE;
        }
        filter(ofp, code);
        fclose(ofp);
      }
      break;
    case 'm':
      compile(bytecode, &bytecode_size, code);
      show_mnemonic(stdout, bytecode, bytecode_size);
      break;
    case 't':
      if (param.out_filename == NULL) {
        translate(stdout, code);
      } else {
        if ((ofp = fopen(param.out_filename, "w")) == NULL) {
          fprintf(stderr, "Unable to open file: %s\n", param.out_filename);
          return EXIT_FAILURE;
        }
        translate(ofp, code);
        fclose(ofp);
      }
      break;
    default:
      compile(bytecode, &bytecode_size, code);
      execute(bytecode);
      break;
  }
  return EXIT_SUCCESS;
}


/*!
 * @brief Parse comamnd-line arguments and set parameters.
 *
 * 'argv' is sorted after called getopt_long().
 * @param [out]    param  Parameters of this program
 * @param [in]     argc   A number of command-line arguments
 * @param [in,out] argv   Coomand-line arguments
 */
static void
parse_arguments(Param *param, int argc, char *argv[])
{
  static const struct option opts[] = {
    {"bytecode",  no_argument,       NULL, 'b'},
    {"filter",    no_argument,       NULL, 'f'},
    {"help",      no_argument,       NULL, 'h'},
    {"mnemonic",  no_argument,       NULL, 'm'},
    {"output",    required_argument, NULL, 'o'},
    {"translate", no_argument,       NULL, 't'},
    {0, 0, 0, 0}  /* must be filled with zero */
  };
  int ret;
  int optidx = 0;
  while ((ret = getopt_long(argc, argv, "bfhmo:t", opts, &optidx)) != -1) {
    switch (ret) {
      case 'b':  /* -b, --bytecode */
      case 'f':  /* -f, --filter */
      case 'm':  /* -n or --nocompile */
      case 't':  /* -t or --translate */
        param->mode = ret;
        break;
      case 'h':  /* -h, --help */
        show_usage(argv[0]);
        exit(EXIT_SUCCESS);
      case 'o':  /* -o or --output */
        param->out_filename = optarg;
        break;
      case '?':  /* unknown option */
        show_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  if (optind != argc - 1) {
    fputs("Please specify one whitespace source code\n", stderr);
    show_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  param->in_filename = argv[optind];
}


/*!
 * @brief Show usage of this program and exit
 * @param [in] progname  A name of this program
 */
static void
show_usage(const char *progname)
{
  printf(
      "[Usage]\n"
      "  $ %s FILE [options]\n"
      "[Options]\n"
      "  -b, --bytecode\n"
      "    Show code in hexadecimal\n"
      "  -f, --filter\n"
      "    Visualize whitespace source code\n"
      "  -h, --help\n"
      "    Show help and exit\n"
      "  -m, --mnemonic\n"
      "    Show byte code in mnemonic format\n"
      "  -o FILE, --output=FILE\n"
      "    Specify output filename\n"
      "  -t, --translate\n"
      "    Translate brainfuck to C source code\n", progname);
}




/* ------------------------------------------------------------------------- *
 * Interpretor                                                               *
 * ------------------------------------------------------------------------- */
/*!
 * @brief Execute whitespace
 * @param [in] bytecode  Bytecode of whitespace
 */
static void
execute(const unsigned char *bytecode)
{
  static int heap[HEAP_SIZE] = {0};
  static size_t call_stack[CALL_STACK_SIZE] = {0};
  size_t call_stack_idx = 0;
  const unsigned char *base = bytecode;
  int a = 0, b = 0;
  for (; *bytecode; bytecode++) {
    switch (*bytecode) {
      case STACK_PUSH:
        bytecode++;
        stack_push(*((const WsInt *) bytecode));
        bytecode += sizeof(WsInt) - 1;
        break;
      case STACK_DUP_N:
        bytecode++;
        stack_dup_n((size_t) *((const WsInt *) bytecode));
        bytecode += sizeof(WsInt) - 1;
        break;
      case STACK_DUP:
        stack_dup_n(0);
        break;
      case STACK_SLIDE:
        bytecode++;
        stack_slide((size_t) *((const WsInt *) bytecode));
        bytecode += sizeof(WsInt) - 1;
        break;
      case STACK_SWAP:
        stack_swap();
        break;
      case STACK_DISCARD:
        stack_pop();
        break;
      case ARITH_ADD:
        a = stack_pop();
        b = stack_pop();
        stack_push(b + a);
        break;
      case ARITH_SUB:
        a = stack_pop();
        b = stack_pop();
        stack_push(b - a);
        break;
      case ARITH_MUL:
        a = stack_pop();
        b = stack_pop();
        stack_push(b * a);
        break;
      case ARITH_DIV:
        a = stack_pop();
        b = stack_pop();
        assert(b != 0);
        stack_push(b / a);
        break;
      case ARITH_MOD:
        a = stack_pop();
        b = stack_pop();
        assert(b != 0);
        stack_push(b % a);
        break;
      case HEAP_STORE:
        a = stack_pop();
        b = stack_pop();
        assert(0 <= b && b < (int) LENGTHOF(heap));
        heap[b] = a;
        break;
      case HEAP_LOAD:
        a = stack_pop();
        assert(0 <= a && a < (int) LENGTHOF(heap));
        stack_push(heap[a]);
        break;
      case FLOW_GOSUB:
        call_stack[call_stack_idx++] = (size_t) (ADDR_DIFF(bytecode, base)) + sizeof(WsAddrInt);
        bytecode++;
        bytecode = &base[*((const WsAddrInt *) bytecode)] - 1;
        break;
      case FLOW_JUMP:
        bytecode++;
        bytecode = &base[*((const WsAddrInt *) bytecode)] - 1;
        break;
      case FLOW_BEZ:
        if (!stack_pop()) {
          bytecode++;
          bytecode = &base[*((const WsAddrInt *) bytecode)] - 1;
        } else {
          bytecode += sizeof(WsAddrInt);
        }
        break;
      case FLOW_BLTZ:
        if (stack_pop() < 0) {
          bytecode++;
          bytecode = &base[*((const WsAddrInt *) bytecode)] - 1;
        } else {
          bytecode += sizeof(WsAddrInt);
        }
        break;
      case FLOW_ENDSUB:
        bytecode = &base[call_stack[--call_stack_idx]];
        break;
      case IO_PUT_CHAR:
        putchar(stack_pop());
        break;
      case IO_PUT_NUM:
        printf("%d", stack_pop());
        break;
      case IO_READ_CHAR:
        a = stack_pop();
        assert(0 <= a && a < (int) LENGTHOF(heap));
        heap[a] = getchar();
        break;
      case IO_READ_NUM:
        a = stack_pop();
        assert(0 <= a && a < (int) LENGTHOF(heap));
        scanf("%d", &heap[a]);
        break;
      case FLOW_HALT:
        printf("HALT\n");
        break;
      default:
        fprintf(stderr, "Undefined instruction is detected [%02x]\n", *bytecode);
    }
  }
}


/*!
 * @brief Compile whitespace source code into bytecode
 * @param [out] bytecode  Bytecode buffer
 * @param [in]  code      Brainfuck source code
 */
static void
compile(unsigned char *bytecode, size_t *bytecode_size, const char *code)
{
  unsigned char *base = bytecode;
  for (; *code != '\0'; code++) {
    switch (*code) {
      case ' ':   /* Stack Manipulation */
        gen_stack_code(&bytecode, &code);
        break;
      case '\t':  /* Arithmetic, Heap Access or I/O */
        switch (*++code) {
          case ' ':  /* Arithmetic */
            gen_arith_code(&bytecode, &code);
            break;
          case '\t':  /* Heap Access */
            gen_heap_code(&bytecode, &code);
            break;
          case '\n':  /* I/O */
            gen_io_code(&bytecode, &code);
            break;
        }
        break;
      case '\n':  /* Flow Control */
        gen_flow_code(&bytecode, &code, base);
        break;
    }
  }
  *bytecode_size = (size_t) ADDR_DIFF(bytecode, base);
  free_label_info_list(label_info_list);
}


/*!
 * @brief Generate bytecode about stack manipulation
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 */
static void
gen_stack_code(unsigned char **bytecode_ptr, const char **code_ptr)
{
  unsigned char *bytecode = *bytecode_ptr;
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      *bytecode++ = STACK_PUSH;
      *((WsInt *) bytecode) = read_nstr(&code);
      bytecode += sizeof(WsInt);
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          *bytecode++ = STACK_DUP_N;
          *((WsInt *) bytecode) = read_nstr(&code);
          bytecode += sizeof(WsInt);
          break;
        case '\t':
          *bytecode++ = STACK_SLIDE;
          *((WsInt *) bytecode) = read_nstr(&code);
          bytecode += sizeof(WsInt);
          break;
        case '\n':
          fputs("Undefined Stack manipulation command is detected: [S][TN]\n", stderr);
          break;
      }
      break;
    case '\n':
      switch (*++code) {
        case ' ':
          *bytecode++ = STACK_DUP_N;
          *((WsInt *) bytecode) = 0;
          bytecode += sizeof(WsInt);
          break;
        case '\t':
          *bytecode++ = STACK_SWAP;
          break;
        case '\n':
          *bytecode++ = STACK_DISCARD;
          break;
      }
      break;
  }
  *bytecode_ptr = bytecode;
  *code_ptr = code;
}


/*!
 * @brief Generate bytecode about arithmetic
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 */
static void
gen_arith_code(unsigned char **bytecode_ptr, const char **code_ptr)
{
  unsigned char *bytecode = *bytecode_ptr;
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      switch (*++code) {
        case ' ':
          *bytecode++ = ARITH_ADD;
          break;
        case '\t':
          *bytecode++ = ARITH_SUB;
          break;
        case '\n':
          *bytecode++ = ARITH_MUL;
          break;
      }
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          *bytecode++ = ARITH_DIV;
          break;
        case '\t':
          *bytecode++ = ARITH_MOD;
          break;
        case '\n':
          fputs("Undefined arithmetic command is detected: [TS][TN]\n", stderr);
          break;
      }
      break;
    case '\n':
      fputs("Undefined arithmetic command is detected: [TS][N]\n", stderr);
      break;
  }
  *bytecode_ptr = bytecode;
  *code_ptr = code;
}


/*!
 * @brief Generate bytecode about heap access
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 */
static void
gen_heap_code(unsigned char **bytecode_ptr, const char **code_ptr)
{
  unsigned char *bytecode = *bytecode_ptr;
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      *bytecode++ = HEAP_STORE;
      break;
    case '\t':
      *bytecode++ = HEAP_LOAD;
      break;
    case '\n':
      fputs("Undefined heap access command is detected: [TT][N]\n", stderr);
      break;
  }
  *bytecode_ptr = bytecode;
  *code_ptr = code;
}


/*!
 * @brief Generate bytecode about flow control
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 * @param [in]     base          Base address of the bytecode buffer
 */
static void
gen_flow_code(unsigned char **bytecode_ptr, const char **code_ptr, unsigned char *base)
{
  unsigned char *bytecode = *bytecode_ptr;
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      switch (*++code) {
        case ' ':
          process_label_define(&bytecode, &code, base);
          break;
        case '\t':
          *bytecode++ = FLOW_GOSUB;
          process_label_jump(&bytecode, &code, base);
          break;
        case '\n':
          *bytecode++ = FLOW_JUMP;
          process_label_jump(&bytecode, &code, base);
          break;
      }
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          *bytecode++ = FLOW_BEZ;
          process_label_jump(&bytecode, &code, base);
          break;
        case '\t':
          *bytecode++ = FLOW_BLTZ;
          process_label_jump(&bytecode, &code, base);
          break;
        case '\n':
          *bytecode++ = FLOW_ENDSUB;
          break;
      }
      break;
    case '\n':
      if (*++code == '\n') {
        *bytecode++ = FLOW_HALT;
      } else {
        fputs("Undefined flow control command is detected: [N][S/T]\n", stderr);
      }
      break;
  }
  *bytecode_ptr = bytecode;
  *code_ptr = code;
}


/*!
 * @brief Generate bytecode about I/O
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 */
static void
gen_io_code(unsigned char **bytecode_ptr, const char **code_ptr)
{
  unsigned char *bytecode = *bytecode_ptr;
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      switch (*++code) {
        case ' ':
          *bytecode++ = IO_PUT_CHAR;
          break;
        case '\t':
          *bytecode++ = IO_PUT_NUM;
          break;
        case '\n':
          fputs("Undefined I/O command is detected: [TN][SN]\n", stderr);
          break;
      }
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          *bytecode++ = IO_READ_CHAR;
          break;
        case '\t':
          *bytecode++ = IO_READ_NUM;
          break;
        case '\n':
          fputs("Undefined I/O command is detected: [TN][TN]\n", stderr);
          break;
      }
      break;
    case '\n':
      fputs("Undefined I/O command is detected: [TN][N]\n", stderr);
      break;
  }
  *bytecode_ptr = bytecode;
  *code_ptr = code;
}


/*!
 * @brief Check given label is already defined or not
 *
 * If label is already defined, return the label information
 * @param [in] label  Label you want to check
 * @return  Label information
 */
static LabelInfo *
search_label(const char *label)
{
  size_t i;
  for (i = 0; i < n_label_info; i++) {
    if (!strcmp(label, label_info_list[i]->label)) {
      return label_info_list[i];
    }
  }
  return NULL;
}


/*!
 * @brief Write where to jump to the bytecode
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 * @param [in]     base          Base address of the bytecode buffer
 */
static void
process_label_define(unsigned char **bytecode_ptr, const char **code_ptr, unsigned char *base)
{
  const char *code = *code_ptr;
  unsigned char *bytecode = *bytecode_ptr;
  char *label = read_label(&code);
  LabelInfo *label_info = search_label(label);

  if (label_info == NULL) {
    add_label(label, (WsAddrInt) ADDR_DIFF(bytecode, base));
  } else {
    if (label_info->addr == UNDEF_ADDR) {
      int i;
      for (i = 0; i < label_info->n_undef; i++) {
        *((WsAddrInt *) &base[label_info->undef_list[i]]) = (WsAddrInt) ADDR_DIFF(bytecode, base);
      }
      label_info->addr = (WsAddrInt) ADDR_DIFF(bytecode, base);
      free(label_info->undef_list);
      label_info->undef_list = NULL;
    } else {
      fputs("Duplicate label definition\n", stderr);
    }
  }
  *code_ptr = code;
  *bytecode_ptr = bytecode;
}


/*!
 * @brief Write where to jump to the bytecode
 *
 * If label is not defined yet, write it after label is defined.
 * @param [out]    bytecode_ptr  Pointer to bytecode buffer
 * @param [in,out] code_ptr      pointer to whitespace source code
 * @param [in]     base          Base address of the bytecode buffer
 */
static void
process_label_jump(unsigned char **bytecode_ptr, const char **code_ptr, unsigned char *base)
{
  const char *code = *code_ptr;
  unsigned char *bytecode = *bytecode_ptr;
  char *label = read_label(&code);
  LabelInfo *label_info = search_label(label);

  if (label_info == NULL) {
    add_undef_label(label, (WsAddrInt) ADDR_DIFF(bytecode, base));
  } else if (label_info->addr == UNDEF_ADDR) {
    label_info->undef_list[label_info->n_undef++] = (WsAddrInt) ADDR_DIFF(bytecode, base);
  } else {
    *((WsAddrInt *) bytecode) = label_info->addr;
  }
  bytecode += sizeof(WsAddrInt);
  *code_ptr = code;
  *bytecode_ptr = bytecode;
}


/*!
 * @brief Add label information to the label list
 * @param [in] _label  Label name
 * @param [in] addr    Label position
 */
static void
add_label(const char *_label, WsAddrInt addr)
{
  char *label = (char *) calloc(strlen(_label) + 1, sizeof(char));
  LabelInfo *label_info = (LabelInfo *) calloc(1, sizeof(LabelInfo));

  if (label == NULL || label_info == NULL) {
    fprintf(stderr, "Failed to allocate heap for label\n");
    exit(EXIT_FAILURE);
  }
  strcpy(label, _label);

  free(label_info->undef_list);
  label_info->undef_list = NULL;
  label_info->label = label;
  label_info->addr = addr;
  label_info->n_undef = 0;
  label_info_list[n_label_info++] = label_info;
}


/*!
 * @brief Add unseen/undefined label to the label list
 * @param [in] _label  Label name
 * @param [in] pos     The position given label was found
 */
static void
add_undef_label(const char *_label, WsAddrInt pos)
{
  char *label = (char *) calloc(strlen(_label) + 1, sizeof(char));
  LabelInfo *label_info = (LabelInfo *) calloc(1, sizeof(LabelInfo));
  label_info->undef_list = (WsAddrInt *) calloc(UNDEF_LIST_SIZE, sizeof(WsAddrInt));

  if (label == NULL || label_info == NULL || label_info->undef_list == NULL) {
    fprintf(stderr, "Failed to allocate heap for label\n");
    exit(EXIT_FAILURE);
  }
  strcpy(label, _label);

  label_info->undef_list[0] = pos;
  label_info->label = label;
  label_info->addr = UNDEF_ADDR;
  label_info->n_undef = 1;
  label_info_list[n_label_info++] = label_info;
}


/*!
 * @brief Free label informations
 * @param [in] label_info_list  Label list
 */
static void
free_label_info_list(LabelInfo *label_info_list[])
{
  size_t i = 0;
  for (i = 0; i < n_label_info; i++) {
    free(label_info_list[i]->label);
    free(label_info_list[i]->undef_list);
    free(label_info_list[i]);
  }
}




/* ------------------------------------------------------------------------- *
 * Stack Manipulation (IMP: [Space])                                         *
 * ------------------------------------------------------------------------- */
/*!
 * @brief Push given number onto the stack
 * @param [in] e  A number you want to push onto the stack
 */
static void
stack_push(WsInt e)
{
  assert(stack_idx < LENGTHOF(stack));
  stack[stack_idx++] = e;
}


/*!
 * @brief Pop out one element from the top of the stack
 * @return  An element of the top of the stack
 */
static WsInt
stack_pop(void)
{
  assert(stack_idx > 0);
  return stack[--stack_idx];
}


/*!
 * @brief Copy the nth item on the stack onto the top of the stack
 */
static void
stack_dup_n(size_t n)
{
  assert(n < stack_idx && stack_idx < LENGTHOF(stack) - 1);
  stack[stack_idx] = stack[stack_idx - (n + 1)];
  stack_idx++;
}


/*!
 * @brief Slide n items off the stack, keeping the top item
 * @param [in] n  The number of items you want to slide off the stack
 */
static void
stack_slide(size_t n)
{
  assert(stack_idx > n);
  stack[stack_idx - (n + 1)] = stack[stack_idx - 1];
  stack_idx -= n;
}


/*!
 * @brief Swap the top two items on the stack
 */
static void
stack_swap(void)
{
  assert(stack_idx > 1);
  SWAP(int, &stack[stack_idx - 1], &stack[stack_idx - 2]);
}


/*!
 * @brief Read whitespace-source code characters and push into given array.
 * @param [in,out] fp      File pointer to the whitespace source code
 * @param [out]    code    The array you want to store the source code
 * @param [in]     length  Max size of given array of code
 * @return Status-code
 */
static int
read_file(FILE *fp, char *code, size_t length)
{
  int    ch;
  size_t cnt = 0;
  for (; (ch = fgetc(fp)) != EOF; cnt++) {
    if (cnt > length) {
      fprintf(stderr, "Buffer overflow!\n");
      return FALSE;
    }
    switch (ch) {
      case ' ':
      case '\n':
      case '\t':
        *code++ = (char) ch;
        break;
    }
  }
  return TRUE;
}




/* ------------------------------------------------------------------------- *
 * Whitespace translator                                                     *
 * ------------------------------------------------------------------------- */
/*!
 * @brief Translate whitespace source code into C source code
 * @param [in,out] fp    output file pointer
 * @param [in]     code  Pointer to Whitespace source code buffer
 * @return Status-code
 */
static int
translate(FILE *fp, const char *code)
{
  print_code_header(fp);
  for (; *code != '\0'; code++) {
    switch (*code) {
      case ' ':   /* Stack Manipulation */
        print_stack_code(fp, &code);
        break;
      case '\t':  /* Arithmetic, Heap Access or I/O */
        switch (*++code) {
          case ' ':  /* Arithmetic */
            print_arith_code(fp, &code);
            break;
          case '\t':  /* Heap Access */
            print_heap_code(fp, &code);
            break;
          case '\n':  /* I/O */
            print_io_code(fp, &code);
            break;
        }
        break;
      case '\n':  /* Flow Control */
        print_flow_code(fp, &code);
        break;
    }
  }
  print_code_footer(fp);
  return TRUE;
}


/*!
 * @brief Print C source code about stack manipulation
 * @param [in,out] fp    output file pointer
 * @param [in]     code  Pointer to Whitespace source code pointer
 */
static void
print_stack_code(FILE *fp, const char **code_ptr)
{
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      fprintf(fp, INDENT_STR "push(%d);\n", read_nstr(&code));
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          fprintf(fp, INDENT_STR "dup_n(%d);\n", read_nstr(&code));
          break;
        case '\t':
          fprintf(fp, INDENT_STR "slide(%d);\n", read_nstr(&code));
          break;
        case '\n':
          fputs("Undefined Stack manipulation command is detected: [S][TN]\n", stderr);
          break;
      }
      break;
    case '\n':
      switch (*++code) {
        case ' ':
          fputs(INDENT_STR "dup_n(0);\n", fp);
          break;
        case '\t':
          fputs(INDENT_STR "swap();\n", fp);
          break;
        case '\n':
          fputs(INDENT_STR "pop();\n", fp);
          break;
      }
      break;
  }
  *code_ptr = code;
}


/*!
 * @brief Print C source code about arithmetic
 * @param [in,out] fp    output file pointer
 * @param [in]     code  Pointer to Whitespace source code pointer
 */
static void
print_arith_code(FILE *fp, const char **code_ptr)
{
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      switch (*++code) {
        case ' ':
          fputs(INDENT_STR "arith_add();\n", fp);
          break;
        case '\t':
          fputs(INDENT_STR "arith_sub();\n", fp);
          break;
        case '\n':
          fputs(INDENT_STR "arith_mul();\n", fp);
          break;
      }
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          fputs(INDENT_STR "arith_div();\n", fp);
          break;
        case '\t':
          fputs(INDENT_STR "arith_mod();\n", fp);
          break;
        case '\n':
          fputs("Undefined arithmetic command is detected: [TS][TN]\n", stderr);
          break;
      }
      break;
    case '\n':
      fputs("Undefined arithmetic command is detected: [TS][N]\n", stderr);
      break;
  }
  *code_ptr = code;
}


/*!
 * @brief Print C source code about heap access
 * @param [in,out] fp    output file pointer
 * @param [in]     code  Pointer to Whitespace source code pointer
 */
static void
print_heap_code(FILE *fp, const char **code_ptr)
{
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      fputs(INDENT_STR "heap_store();\n", fp);
      break;
    case '\t':
      fputs(INDENT_STR "heap_read();\n", fp);
    break;
    case '\n':
      fputs("Undefined heap access command is detected: [TT][N]\n", stderr);
      break;
  }
  *code_ptr = code;
}


/*!
 * @brief Print C source code about flow control
 * @param [in,out] fp    output file pointer
 * @param [in]     code  Pointer to Whitespace source code pointer
 */
static void
print_flow_code(FILE *fp, const char **code_ptr)
{
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      switch (*++code) {
        case ' ':
          fprintf(fp, "\n%s:\n", read_label(&code));
          break;
        case '\t':
          fprintf(fp,
              INDENT_STR "if (!setjmp(call_stack[call_stack_idx++])) {\n"
              INDENT_STR INDENT_STR "goto %s;\n"
              INDENT_STR "}\n",
              read_label(&code));
          break;
        case '\n':
          fprintf(fp, INDENT_STR "goto %s;\n", read_label(&code));
          break;
      }
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          fprintf(fp,
              INDENT_STR "if (!pop()) {\n"
              INDENT_STR INDENT_STR "goto %s;\n"
              INDENT_STR "}\n",
              read_label(&code));
          break;
        case '\t':
          fprintf(fp,
              INDENT_STR "if (pop() < 0) {\n"
              INDENT_STR INDENT_STR "goto %s;\n"
              INDENT_STR "}\n",
              read_label(&code));
          break;
        case '\n':
          fputs(INDENT_STR "longjmp(call_stack[--call_stack_idx], 1);\n", fp);
          break;
      }
      break;
    case '\n':
      if (*++code == '\n') {
        fputs(INDENT_STR "exit(EXIT_SUCCESS);\n", fp);
      } else {
        fputs("Undefined flow control command is detected: [N][S/T]\n", stderr);
      }
      break;
  }
  *code_ptr = code;
}


/*!
 * @brief Print C source code about I/O
 * @param [in,out] fp    output file pointer
 * @param [in]     code  Pointer to Whitespace source code pointer
 */
static void
print_io_code(FILE *fp, const char **code_ptr)
{
  const char *code = *code_ptr;
  switch (*++code) {
    case ' ':
      switch (*++code) {
        case ' ':
          fputs(INDENT_STR "putchar(pop());\n", fp);
          break;
        case '\t':
          fputs(INDENT_STR "printf(\"%d\", pop());\n", fp);
          break;
        case '\n':
          fputs("Undefined I/O command is detected: [TN][SN]\n", stderr);
          break;
      }
      break;
    case '\t':
      switch (*++code) {
        case ' ':
          fputs(INDENT_STR "heap[pop()] = getchar();\n", fp);
          break;
        case '\t':
          fputs(INDENT_STR "scanf(\"%d\", &heap[pop()]);\n", fp);
          break;
        case '\n':
          fputs("Undefined I/O command is detected: [TN][TN]\n", stderr);
          break;
      }
      break;
    case '\n':
      fputs("Undefined I/O command is detected: [TN][N]\n", stderr);
      break;
  }
  *code_ptr = code;
}


/*!
 * @brief Print the header of translated C-source code
 * @param [in,out] fp  Output file pointer
 */
static void
print_code_header(FILE *fp)
{
  fputs(
      "#include <assert.h>\n"
      "#include <setjmp.h>\n"
      "#include <stdio.h>\n"
      "#include <stdlib.h>\n\n", fp);
  fputs(
      "#ifndef __cplusplus\n"
      "#  if defined(_MSC_VER)\n"
      "#    define inline      __inline\n"
      "#    define __inline__  __inline\n"
      "#  elif !defined(__GNUC__) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)\n"
      "#    define inline\n"
      "#    define __inline\n"
      "#  endif\n"
      "#endif\n\n", fp);
  fprintf(fp,
      "#define STACK_SIZE %d\n"
      "#define HEAP_SIZE %d\n"
      "#define CALL_STACK_SIZE %d\n\n"
      "#define LENGTHOF(array) (sizeof(array) / sizeof((array)[0]))\n"
      "#define SWAP(type, a, b) \\\n"
      INDENT_STR "do { \\\n"
      INDENT_STR INDENT_STR "type __tmp_swap_var__ = *(a); \\\n"
      INDENT_STR INDENT_STR "*(a) = *(b); \\\n"
      INDENT_STR INDENT_STR "*(b) = __tmp_swap_var__; \\\n"
      INDENT_STR "} while (0)\n\n",
      STACK_SIZE, HEAP_SIZE, CALL_STACK_SIZE);
  fputs(
      "inline static int  pop(void);\n"
      "inline static void push(int e);\n"
      "inline static void dup_n(size_t n);\n"
      "inline static void slide(size_t n);\n"
      "inline static void swap(void);\n", fp);
  fputs(
      "inline static void arith_add(void);\n"
      "inline static void arith_sub(void);\n"
      "inline static void arith_mul(void);\n"
      "inline static void arith_div(void);\n"
      "inline static void arith_mod(void);\n", fp);
  fputs(
      "inline static void heap_store(void);\n"
      "inline static void heap_read(void);\n\n", fp);
  fputs(
      "static int stack[STACK_SIZE];\n"
      "static int heap[HEAP_SIZE];\n"
      "static jmp_buf call_stack[CALL_STACK_SIZE];\n"
      "static size_t stack_idx = 0;\n"
      "static size_t call_stack_idx = 0;\n\n\n", fp);
  fputs(
      "int main(void)\n"
      "{\n", fp);
}


/*!
 * @brief Print the footer of translated C-source code
 * @param [in,out] fp  Output file pointer
 */
static void
print_code_footer(FILE *fp)
{
  fputs(
      "\n"
      INDENT_STR "return EXIT_SUCCESS;\n"
      "}\n\n\n", fp);
  fputs(
      "inline static int pop(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx < LENGTHOF(stack));\n"
      INDENT_STR "return stack[--stack_idx];\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void push(int e)\n"
      "{\n"
      INDENT_STR "assert(stack_idx < LENGTHOF(stack));\n"
      INDENT_STR "stack[stack_idx++] = e;\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void dup_n(size_t n)\n"
      "{\n"
      INDENT_STR "assert(n < stack_idx && stack_idx < LENGTHOF(stack) - 1);\n"
      INDENT_STR "stack[stack_idx] = stack[stack_idx - (n + 1)];\n"
      INDENT_STR "stack_idx++;\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void slide(size_t n)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > n);\n"
      INDENT_STR "stack[stack_idx - (n + 1)] = stack[stack_idx - 1];\n"
      INDENT_STR "stack_idx -= n;\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void swap(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > 1);\n"
      INDENT_STR "SWAP(int, &stack[stack_idx - 1], &stack[stack_idx - 2]);\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void arith_add(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > 1);\n"
      INDENT_STR "stack_idx--;\n"
      INDENT_STR "stack[stack_idx - 1] += stack[stack_idx];\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void arith_sub(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > 1);\n"
      INDENT_STR "stack_idx--;\n"
      INDENT_STR "stack[stack_idx - 1] -= stack[stack_idx];\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void arith_mul(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > 1);\n"
      INDENT_STR "stack_idx--;\n"
      INDENT_STR "stack[stack_idx - 1] *= stack[stack_idx];\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void arith_div(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > 1);\n"
      INDENT_STR "stack_idx--;\n"
      INDENT_STR "assert(stack[stack_idx] != 0);\n"
      INDENT_STR "stack[stack_idx - 1] /= stack[stack_idx];\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void arith_mod(void)\n"
      "{\n"
      INDENT_STR "assert(stack_idx > 1);\n"
      INDENT_STR "stack_idx--;\n"
      INDENT_STR "assert(stack[stack_idx] != 0);\n"
      INDENT_STR "stack[stack_idx - 1] %= stack[stack_idx];\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void heap_store(void)\n"
      "{\n"
      INDENT_STR "int value = pop();\n"
      INDENT_STR "int addr  = pop();\n"
      INDENT_STR "assert(0 <= addr && addr < (int) LENGTHOF(heap));\n"
      INDENT_STR "heap[addr] = value;\n"
      "}\n\n\n", fp);
  fputs(
      "inline static void heap_read(void)\n"
      "{\n"
      INDENT_STR "int addr = pop();\n"
      INDENT_STR "assert(0 <= addr && addr < (int) LENGTHOF(heap));\n"
      INDENT_STR "push(heap[addr]);\n"
      "}\n", fp);
}


/*!
 * @brief Read integer and seek program pointer.
 * @param [in,out] code_ptr  Program pointer
 * @return  An integer parsed from source code
 */
static int
read_nstr(const char **code_ptr)
{
  const char *code = *code_ptr;
  int is_positive = 1;
  int sum = 0;
  switch (*++code) {
    case '\t':
      is_positive = 0;
      break;
    case '\n':
      *code_ptr = code;
      return 0;
  }
  while (*++code != '\n') {
    sum <<= 1;
    if (*code == '\t') {
      sum++;
    }
  }
  *code_ptr = code;
  return is_positive ? sum : -sum;
}


/*!
 * @brief Read label and convert it into strings.
 * @param [in,out] code_ptr  Program pointer
 * @return  Converted label
 */
static char *
read_label(const char **code_ptr)
{
  static char label_name[MAX_LABEL_LENGTH];
  char *ptr = label_name;
  const char *code = *code_ptr;
  char ch;

  while ((ch = *++code) != '\n') {
    switch (ch) {
      case ' ':
        *ptr++ = 'S';
        break;
      case '\t':
        *ptr++ = 'T';
        break;
    }
  }
  *ptr = '\0';
  *code_ptr = code;
  return label_name;
}


/*!
 * @brief Show byte code in hexadecimal
 * @param [in] bytecode       Whitespace byte code
 * @param [in] bytecode_size  Size of whitespace byte code
 */
static void
show_bytecode(const unsigned char *bytecode, size_t bytecode_size)
{
  size_t i, j;
  size_t quot = bytecode_size / 16;
  size_t rem  = bytecode_size % 16;
  int addr_cnt = 0;

  puts("ADDRESS  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
  for (i = 0; i < quot; i++) {
    printf("0x%04x: ", addr_cnt);
    addr_cnt += 16;
    for (j = 0; j < 16; j++) {
      printf(" %02x", *bytecode++);
    }
    puts("");
  }
  printf("0x%04x: ", addr_cnt);
  for (i = 0; i < rem; i++) {
    printf(" %02x", *bytecode++);
  }
  puts("");
}


/*!
 * @brief Show the byte code in mnemonic format.
 * @param [in] fp             Output file pointer
 * @param [in] bytecode       Whitespace byte code
 * @param [in] bytecode_size  Size of whitespace byte code
 */
static void
show_mnemonic(FILE *fp, const unsigned char *bytecode, size_t bytecode_size)
{
  const unsigned char *end;
  const unsigned char *base = bytecode;
  for (end = bytecode + bytecode_size; bytecode < end; bytecode++) {
    fprintf(fp, "%04d: ", (int) ADDR_DIFF(bytecode, base));
    switch (*bytecode) {
      case STACK_PUSH:
        bytecode++;
        fprintf(fp, "STACK_PUSH %d\n", *((const WsInt *) bytecode));
        bytecode += sizeof(WsInt) - 1;
        break;
      case STACK_DUP_N:
        bytecode++;
        fprintf(fp, "STACK_DUP_N %d\n", *((const WsInt *) bytecode));
        bytecode += sizeof(WsInt) - 1;
        break;
      case STACK_DUP:
        fprintf(fp, "STACK_DUP\n");
        break;
      case STACK_SLIDE:
        bytecode++;
        fprintf(fp, "STACK_SLIDE %d\n", *((const WsInt *) bytecode));
        bytecode += sizeof(WsInt) - 1;
        break;
      case STACK_SWAP:
        fputs("STACK_SWAP\n", fp);
        break;
      case STACK_DISCARD:
        fputs("STACK_POP\n", fp);
        break;
      case ARITH_ADD:
        fputs("ARITH_ADD\n", fp);
        break;
      case ARITH_SUB:
        fputs("ARITH_SUB\n", fp);
        break;
      case ARITH_MUL:
        fputs("ARITH_MUL\n", fp);
        break;
      case ARITH_DIV:
        fputs("ARITH_DIV\n", fp);
        break;
      case ARITH_MOD:
        fputs("ARITH_MOD\n", fp);
        break;
      case HEAP_STORE:
        fputs("HEAP_STORE\n", fp);
        break;
      case HEAP_LOAD:
        fputs("HEAP_LOAD\n", fp);
        break;
      case FLOW_GOSUB:
        bytecode++;
        fprintf(fp, "FLOW_GOSUB %u\n", *((const WsAddrInt *) bytecode));
        bytecode += sizeof(WsAddrInt) - 1;
        break;
      case FLOW_JUMP:
        bytecode++;
        fprintf(fp, "FLOW_JUMP %u\n", *((const WsAddrInt *) bytecode));
        bytecode += sizeof(WsAddrInt) - 1;
        break;
      case FLOW_BEZ:
        bytecode++;
        fprintf(fp, "FLOW_BEZ %u\n", *((const WsAddrInt *) bytecode));
        bytecode += sizeof(WsAddrInt) - 1;
        break;
      case FLOW_BLTZ:
        bytecode++;
        fprintf(fp, "FLOW_BLTZ %u\n", *((const WsAddrInt *) bytecode));
        bytecode += sizeof(WsAddrInt) - 1;
        break;
      case FLOW_HALT:
        fputs("FLOW_HALT\n", fp);
        break;
      case FLOW_ENDSUB:
        fputs("FLOW_ENDSUB\n", fp);
        break;
      case IO_PUT_CHAR:
        fputs("IO_PUT_CHAR\n", fp);
        break;
      case IO_PUT_NUM:
        fputs("IO_PUT_NUM\n", fp);
        break;
      case IO_READ_CHAR:
        fputs("IO_READ_CHAR\n", fp);
        break;
      case IO_READ_NUM:
        fputs("IO_READ_NUM\n", fp);
        break;
      default:
        fprintf(fp, "UNDEFINED_INSTRUCTION [0x%02x]\n", *bytecode);
    }
  }
}


/*!
 * @brief Visualize the source code using S and T instead of space or tab.
 * @param [in,out] fp    Output file pointer
 * @param [in]     code  Whitespace source code
 */
static void
filter(FILE *fp, const char *code)
{
  for (; *code != '\0'; code++) {
    switch (*code) {
      case ' ':
        fputc('S', fp);
        break;
      case '\t':
        fputc('T', fp);
        break;
      case '\n':
        fputc('\n', fp);
        break;
    }
  }
}
