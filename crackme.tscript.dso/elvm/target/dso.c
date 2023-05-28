#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ir/ir.h>
#include <target/util.h>

#define REG_SCRATCH 7
#define MAGIC_TRAMPOLINE_ZONE 0xffffff
#define DEBUG_SCRIPT 0
#define DEBUG_HOST 0

enum CompiledInstructions
{
  OP_FUNC_DECL,              // 0
  OP_CREATE_OBJECT,          // 1
  OP_ADD_OBJECT,             // 2
  OP_END_OBJECT,             // 3
  OP_FINISH_OBJECT,          // 4
  OP_JMPIFFNOT,              // 5
  OP_JMPIFNOT,               // 6
  OP_JMPIFF,                 // 7
  OP_JMPIF,                  // 8
  OP_JMPIFNOT_NP,            // 9
  OP_JMPIF_NP,               // 10
  OP_JMP,                    // 11
  OP_RETURN,                 // 12
  OP_RETURN_VOID,            // 13
  OP_RETURN_FLT,             // 14
  OP_RETURN_UINT,            // 15
  OP_CMPEQ,                  // 16
  OP_CMPGR,                  // 17
  OP_CMPGE,                  // 18
  OP_CMPLT,                  // 19
  OP_CMPLE,                  // 20
  OP_CMPNE,                  // 21
  OP_XOR,                    // 22
  OP_MOD,                    // 23
  OP_BITAND,                 // 24
  OP_BITOR,                  // 25
  OP_NOT,                    // 26
  OP_NOTF,                   // 27
  OP_ONESCOMPLEMENT,         // 28
  OP_SHR,                    // 29
  OP_SHL,                    // 30
  OP_AND,                    // 31
  OP_OR,                     // 32
  OP_ADD,                    // 33
  OP_SUB,                    // 34
  OP_MUL,                    // 35
  OP_DIV,                    // 36
  OP_NEG,                    // 37
  OP_INC,                    // 38
  OP_SETCURVAR,              // 39
  OP_SETCURVAR_CREATE,       // 40
  OP_SETCURVAR_ARRAY,        // 41
  OP_SETCURVAR_ARRAY_CREATE, // 42
  OP_LOADVAR_UINT,           // 43
  OP_LOADVAR_FLT,            // 44
  OP_LOADVAR_STR,            // 45
  OP_SAVEVAR_UINT,           // 46
  OP_SAVEVAR_FLT,            // 47
  OP_SAVEVAR_STR,            // 48
  OP_LOAD_LOCAL_VAR_UINT,    // 49
  OP_LOAD_LOCAL_VAR_FLT,     // 50
  OP_LOAD_LOCAL_VAR_STR,     // 51
  OP_SAVE_LOCAL_VAR_UINT,    // 52
  OP_SAVE_LOCAL_VAR_FLT,     // 53
  OP_SAVE_LOCAL_VAR_STR,     // 54
  OP_SETCUROBJECT,           // 55
  OP_SETCUROBJECT_NEW,       // 56
  OP_SETCUROBJECT_INTERNAL,  // 57
  OP_SETCURFIELD,            // 58
  OP_SETCURFIELD_ARRAY,      // 59
  OP_SETCURFIELD_TYPE,       // 60
  OP_LOADFIELD_UINT,         // 61
  OP_LOADFIELD_FLT,          // 62
  OP_LOADFIELD_STR,          // 63
  OP_SAVEFIELD_UINT,         // 64
  OP_SAVEFIELD_FLT,          // 65
  OP_SAVEFIELD_STR,          // 66
  OP_POP_STK,                // 67
  OP_LOADIMMED_UINT,         // 68
  OP_LOADIMMED_FLT,          // 69
  OP_TAG_TO_STR,             // 70
  OP_LOADIMMED_STR,          // 71
  OP_DOCBLOCK_STR,           // 72
  OP_LOADIMMED_IDENT,        // 73
  OP_CALLFUNC,               // 74
  OP_ADVANCE_STR_APPENDCHAR, // 75
  OP_REWIND_STR,             // 76
  OP_TERMINATE_REWIND_STR,   // 77
  OP_COMPARE_STR,            // 78
  OP_PUSH,                   // 79
  OP_PUSH_FRAME,             // 80
  OP_ASSERT,                 // 81
  OP_BREAK,                  // 82
  OP_ITER_BEGIN,             // 83
  OP_ITER_BEGIN_STR,         // 84
  OP_ITER,                   // 85
  OP_ITER_END,               // 86
  OP_INVALID,                // 87
  MAX_OP_CODELEN
};

enum {
  FunctionCall = 0,
  StaticCall,
  MethodCall,
  ParentCall
};

struct func {
  int start_ip;
  int code_start_ip;
  int end_ip;

  int* code;
  int code_size;
  int code_cap;
};

struct ste {
  int ip;
  int index;
};

struct jmp {
  int ip;
  int pc;
};

struct dso_vm_state {
  int register_offset[7];

  int* code;
  int code_size;
  int code_cap;

  char* global_strings;
  int global_strings_size;
  int global_strings_cap;

  struct ste* stes;
  int stes_size;
  int stes_cap;

  int* labels;
  int labels_cap;

  struct jmp* jmps;
  int jmps_size;
  int jmps_cap;

  int in_func;
  struct func current_func;
};

struct dso_vm_state state;

void add_label(int pc) {
  while (pc >= state.labels_cap) {
    int old_cap = state.labels_cap;
    if (state.labels == NULL) {
      state.labels = malloc(256 * sizeof(int));
      state.labels_cap = 256;
    } else {
      int* new_code = malloc(state.labels_cap * 2 * sizeof(int));
      memcpy(new_code, state.labels, state.labels_cap * sizeof(int));
      free(state.labels);
      state.labels = new_code;
      state.labels_cap = state.labels_cap * 2;
    }
    for (int i = old_cap; i < state.labels_cap; i ++) {
      state.labels[i] = 0;
    }
  }

  if (state.labels[pc] != 0)
    return;

  int ip;
  if (state.in_func) {
    ip = state.current_func.code_start_ip + state.current_func.code_size;
  } else {
    ip = state.code_size;
  }

#if DEBUG_HOST
  fprintf(stderr, "VM[%d] => %d\n", pc, ip);
#endif

  state.labels[pc] = ip;
}

int emit_string(const char* string) {
  // Lookup in global strings
  for (int i = 0; i < state.global_strings_size; i ++) {
    if (strcmp(string, &state.global_strings[i]) == 0) {
      return i;
    }
  }

  int len = strlen(string);
  while ((state.global_strings_size + len) >= state.global_strings_cap) {
    if (state.global_strings == NULL) {
      state.global_strings = malloc(256 * sizeof(char));
      state.global_strings_cap = 256;
    } else {
      char* new_global_strings = malloc(state.global_strings_cap * 2 * sizeof(char));
      memcpy(new_global_strings, state.global_strings, state.global_strings_cap * sizeof(char));
      free(state.global_strings);
      state.global_strings = new_global_strings;
      state.global_strings_cap = state.global_strings_cap * 2;
    }
  }

  int result = state.global_strings_size;
  for (int i = 0; i < len; i ++) {
    state.global_strings[state.global_strings_size] = string[i];
    state.global_strings_size ++;
  }
  state.global_strings[state.global_strings_size] = 0;
  state.global_strings_size ++;

  return result;
}

void emit_op(int op) {
  if (state.in_func) {
    if (state.current_func.code_size >= state.current_func.code_cap) {
      if (state.current_func.code == NULL) {
        state.current_func.code = malloc(256 * sizeof(int));
        state.current_func.code_cap = 256;
      } else {
        int* new_code = malloc(state.current_func.code_cap * 2 * sizeof(int));
        memcpy(new_code, state.current_func.code, state.current_func.code_cap * sizeof(int));
        free(state.current_func.code);
        state.current_func.code = new_code;
        state.current_func.code_cap = state.current_func.code_cap * 2;
      }
    }
    state.current_func.code[state.current_func.code_size] = op;
    state.current_func.code_size ++;
  } else {
    // fprintf(stderr, "%d => %d\n", state.code_size, op);
    if (state.code_size >= state.code_cap) {
      if (state.code == NULL) {
        state.code = malloc(256 * sizeof(int));
        state.code_cap = 256;
      } else {
        int* new_code = malloc(state.code_cap * 2 * sizeof(int));
        memcpy(new_code, state.code, state.code_cap * sizeof(int));
        free(state.code);
        state.code = new_code;
        state.code_cap = state.code_cap * 2;
      }
    }
    state.code[state.code_size] = op;
    state.code_size ++;
  }
}

void emit_uint(int value) {
  emit_op(value);
}

void emit_immed_str(const char* str) {
  emit_op(emit_string(str));
}

void emit_ste(const char* str) {
  if (str == NULL) {
    emit_op(0);
    emit_op(0);
    return;
  }
  int offset = emit_string(str);

  if (state.stes_size >= state.stes_cap) {
    if (state.stes == NULL) {
      state.stes = malloc(256 * sizeof(struct ste));
      state.stes_cap = 256;
    } else {
      struct ste* new_stes = malloc(state.stes_cap * 2 * sizeof(struct ste));
      memcpy(new_stes, state.stes, state.stes_cap * sizeof(struct ste));
      free(state.stes);
      state.stes = new_stes;
      state.stes_cap = state.stes_cap * 2;
    }
  }

  int ste_addr = 0;
  if (state.in_func) {
    ste_addr = state.current_func.code_start_ip + state.current_func.code_size;
  } else {
    ste_addr = state.code_size;
  }

#if DEBUG_HOST
  fprintf(stderr, "STE @ %d => %d\n", ste_addr, offset);
#endif

  state.stes[state.stes_size].ip = ste_addr;
  state.stes[state.stes_size].index = offset;
  state.stes_size ++;

  emit_op(0);
  emit_op(0);
}

void emit_goto(int new_pc) {
  if (state.jmps_size >= state.jmps_cap) {
    if (state.jmps == NULL) {
      state.jmps = malloc(256 * sizeof(struct jmp));
      state.jmps_cap = 256;
    } else {
      struct jmp* new_stes = malloc(state.jmps_cap * 2 * sizeof(struct jmp));
      memcpy(new_stes, state.jmps, state.jmps_cap * sizeof(struct jmp));
      free(state.jmps);
      state.jmps = new_stes;
      state.jmps_cap = state.jmps_cap * 2;
    }
  }

  int jmp_addr = 0;
  if (state.in_func) {
    jmp_addr = state.current_func.code_start_ip + state.current_func.code_size;
  } else {
    jmp_addr = state.code_size;
  }

#if DEBUG_HOST
  fprintf(stderr, "JMP @ %d => %d\n", jmp_addr, new_pc);
#endif

  state.jmps[state.jmps_size].ip = jmp_addr;
  state.jmps[state.jmps_size].pc = new_pc;
  state.jmps_size ++;

  emit_op(0);
}

void start_func(int argc) {
  state.in_func = true;
  state.current_func.code = NULL;
  state.current_func.code_size = 0;
  state.current_func.code_cap = 0;
  state.current_func.start_ip = state.code_size;
  state.current_func.code_start_ip = state.code_size
    + 1 // emit_op(OP_FUNC_DECL);
    + 2 // emit_ste(name); // name
    + 2 // emit_ste(namespace); // namespace
    + 2 // emit_ste(package); // package
    + 1 // emit_uint(1); // hasbody
    + 1 // emit_uint(25); // todo: end ip
    + 1 // emit_uint(argc); // argc
    + 1 // emit_uint(regc); // reg count
    + argc; // emit_uint(arg_regv[i]); // argi reg
}

void end_func(const char* name, const char* namespace, const char* package, int argc, int* arg_regv, int regc) {
  emit_op(OP_RETURN_VOID);
  state.in_func = false;

  state.current_func.end_ip = state.code_size
    + state.current_func.code_size
    + 1 // emit_op(OP_FUNC_DECL);
    + 2 // emit_ste(name); // name
    + 2 // emit_ste(namespace); // namespace
    + 2 // emit_ste(package); // package
    + 1 // emit_uint(1); // hasbody
    + 1 // emit_uint(25); // todo: end ip
    + 1 // emit_uint(argc); // argc
    + 1 // emit_uint(regc); // reg count
    + argc; // emit_uint(arg_regv[i]); // argi reg

  emit_op(OP_FUNC_DECL);
  emit_ste(name); // name
  emit_ste(namespace); // namespace
  emit_ste(package); // package
  emit_uint(1); // hasbody
  emit_uint(state.current_func.end_ip); // todo: end ip
  emit_uint(argc); // argc
  emit_uint(regc); // reg count
  for (int i = 0; i < argc; i ++) {
    emit_uint(arg_regv[i]); // argi reg
  }
  for (int i = 0; i < state.current_func.code_size; i ++) {
    emit_op(state.current_func.code[i]);
  }

  assert(state.code_size == state.current_func.end_ip);
}

void emit_load_src(Inst* inst) {
  if (inst->src.type == REG) {
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[inst->src.reg]);
  } else {
    emit_op(OP_LOADIMMED_UINT);
    emit_uint(inst->src.imm);
  }
}

void emit_load_dst(Inst* inst) {
  emit_op(OP_LOAD_LOCAL_VAR_UINT);
  emit_op(state.register_offset[inst->dst.reg]);
}

char* print_inst(Inst* inst) {
  static char buffer[0x100];

  switch (inst->op) {
    case MOV:   snprintf(buffer, 0x100, "%d: MOV   %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case ADD:   snprintf(buffer, 0x100, "%d: ADD   %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case SUB:   snprintf(buffer, 0x100, "%d: SUB   %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case LOAD:  snprintf(buffer, 0x100, "%d: LOAD  %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case STORE: snprintf(buffer, 0x100, "%d: STORE %s, %s", inst->pc, src_str(inst), reg_names[inst->dst.reg]); break;
    case PUTC:  snprintf(buffer, 0x100, "%d: PUTC  %s", inst->pc, src_str(inst)); break;
    case GETC:  snprintf(buffer, 0x100, "%d: GETC  %s", inst->pc, reg_names[inst->dst.reg]); break;
    case EXIT:  snprintf(buffer, 0x100, "%d: EXIT", inst->pc); break;
    case DUMP:  snprintf(buffer, 0x100, "%d: DUMP", inst->pc); break;
    case EQ:    snprintf(buffer, 0x100, "%d: EQ    %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case NE:    snprintf(buffer, 0x100, "%d: NE    %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case LT:    snprintf(buffer, 0x100, "%d: LT    %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case GT:    snprintf(buffer, 0x100, "%d: GT    %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case LE:    snprintf(buffer, 0x100, "%d: LE    %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case GE:    snprintf(buffer, 0x100, "%d: GE    %s, %s", inst->pc, reg_names[inst->dst.reg], src_str(inst)); break;
    case JEQ:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JEQ   %d, %s, %s", inst->pc, inst->jmp.imm, reg_names[inst->dst.reg], src_str(inst)); } else { snprintf(buffer, 0x100, "%d: JEQ   %s, %s, %s", inst->pc, reg_names[inst->jmp.reg], reg_names[inst->dst.reg], src_str(inst)); } break;
    case JNE:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JNE   %d, %s, %s", inst->pc, inst->jmp.imm, reg_names[inst->dst.reg], src_str(inst)); } else { snprintf(buffer, 0x100, "%d: JNE   %s, %s, %s", inst->pc, reg_names[inst->jmp.reg], reg_names[inst->dst.reg], src_str(inst)); } break;
    case JLT:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JLT   %d, %s, %s", inst->pc, inst->jmp.imm, reg_names[inst->dst.reg], src_str(inst)); } else { snprintf(buffer, 0x100, "%d: JLT   %s, %s, %s", inst->pc, reg_names[inst->jmp.reg], reg_names[inst->dst.reg], src_str(inst)); } break;
    case JGT:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JGT   %d, %s, %s", inst->pc, inst->jmp.imm, reg_names[inst->dst.reg], src_str(inst)); } else { snprintf(buffer, 0x100, "%d: JGT   %s, %s, %s", inst->pc, reg_names[inst->jmp.reg], reg_names[inst->dst.reg], src_str(inst)); } break;
    case JLE:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JLE   %d, %s, %s", inst->pc, inst->jmp.imm, reg_names[inst->dst.reg], src_str(inst)); } else { snprintf(buffer, 0x100, "%d: JLE   %s, %s, %s", inst->pc, reg_names[inst->jmp.reg], reg_names[inst->dst.reg], src_str(inst)); } break;
    case JGE:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JGE   %d, %s, %s", inst->pc, inst->jmp.imm, reg_names[inst->dst.reg], src_str(inst)); } else { snprintf(buffer, 0x100, "%d: JGE   %s, %s, %s", inst->pc, reg_names[inst->jmp.reg], reg_names[inst->dst.reg], src_str(inst)); } break;
    case JMP:   if (inst->jmp.type == IMM) { snprintf(buffer, 0x100, "%d: JMP   %d", inst->pc, inst->jmp.imm); } else { snprintf(buffer, 0x100, "%d: JMP   %s", inst->pc, reg_names[inst->jmp.reg]); } break;
    default: snprintf(buffer, 0x100, "%d: INVALID", inst->pc);
  }
  return buffer;
}

void target_dso(Module* module) {
  (void)module;

  assert(OP_INVALID == 87);

  state.register_offset[A] = 1;
  state.register_offset[B] = 2;
  state.register_offset[C] = 3;
  state.register_offset[D] = 4;
  state.register_offset[BP] = 5;
  state.register_offset[SP] = 6;
  state.code = NULL;
  state.code_size = 0;
  state.code_cap = 0;
  state.in_func = false;
  state.current_func.code = NULL;
  state.current_func.code_size = 0;
  state.current_func.code_cap = 0;

  int arg_regv[1] = {0};

  start_func(1);

  // Init state
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$input");
  emit_op(OP_LOAD_LOCAL_VAR_STR);
  emit_uint(arg_regv[0]);
  emit_op(OP_SAVEVAR_STR);
  emit_op(OP_POP_STK);

  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$i");
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(0);
  emit_op(OP_SAVEVAR_UINT);
  emit_op(OP_POP_STK);

  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste("");
  emit_op(OP_SAVEVAR_STR);
  emit_op(OP_POP_STK);

  // Load memory
  Data* data = module->data;
  for (int mp = 0; data; data = data->next, mp++) {
    emit_op(OP_LOADIMMED_UINT);
    emit_uint(data->v);

    emit_op(OP_LOADIMMED_IDENT);
    emit_ste("mem");
    emit_op(OP_LOADIMMED_UINT);
    emit_uint(mp);
    emit_op(OP_REWIND_STR);
    emit_op(OP_SETCURVAR_ARRAY_CREATE);
    emit_op(OP_POP_STK);
    emit_op(OP_SAVEVAR_UINT);
    emit_op(OP_POP_STK);
  }

  // Emit instructions
  for (Inst* inst = module->text; inst; inst = inst->next) {
#if DEBUG_HOST
    fprintf(stderr, "%s\n", print_inst(inst));
#endif
    add_label(inst->pc);

#if DEBUG_SCRIPT
    emit_op(OP_PUSH_FRAME);
    emit_uint(1);
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste(print_inst(inst));
    if (inst->magic_comment && *inst->magic_comment) {
      emit_op(OP_LOADIMMED_IDENT);
      emit_ste("         ");
      emit_op(OP_REWIND_STR);
      emit_op(OP_LOADIMMED_IDENT);
      emit_ste(inst->magic_comment);
      emit_op(OP_REWIND_STR);
    }
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste("         a=");
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[A]);
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste(" b=");
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[B]);
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste(" c=");
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[C]);
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste(" d=");
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[D]);
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste(" bp=");
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[BP]);
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOADIMMED_IDENT);
    emit_ste(" sp=");
    emit_op(OP_REWIND_STR);
    emit_op(OP_LOAD_LOCAL_VAR_UINT);
    emit_op(state.register_offset[SP]);
    emit_op(OP_REWIND_STR);
    emit_op(OP_PUSH);
    emit_op(OP_CALLFUNC);
    emit_ste("echo");
    emit_ste(NULL);
    emit_uint(FunctionCall);
    emit_op(OP_POP_STK);
#endif

    switch (inst->op) {
    case MOV:
      // dst:reg <- src:imm/reg
      emit_load_src(inst);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(state.register_offset[inst->dst.reg]);
      emit_op(OP_POP_STK);
      break;

    case ADD:
      // dst:reg <- dst:reg + src:imm/reg
      emit_op(OP_LOADIMMED_UINT);
      emit_op(UINT_MAX);
      emit_load_src(inst);
      emit_load_dst(inst);
      emit_op(OP_ADD);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(REG_SCRATCH);
      emit_op(OP_POP_STK);
      emit_op(OP_LOAD_LOCAL_VAR_UINT);
      emit_op(REG_SCRATCH);
      emit_op(OP_BITAND);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(state.register_offset[inst->dst.reg]);
      emit_op(OP_POP_STK);
      break;

    case SUB:
      // dst:reg <- dst:reg - src:imm/reg
      emit_op(OP_LOADIMMED_UINT);
      emit_op(UINT_MAX);
      emit_load_src(inst);
      emit_load_dst(inst);
      emit_op(OP_SUB);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(REG_SCRATCH);
      emit_op(OP_POP_STK);
      emit_op(OP_LOAD_LOCAL_VAR_UINT);
      emit_op(REG_SCRATCH);
      emit_op(OP_BITAND);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(state.register_offset[inst->dst.reg]);
      emit_op(OP_POP_STK);
      break;

    case LOAD:
      // dst:reg <- mem[src:imm/reg]
      emit_op(OP_LOADIMMED_IDENT);
      emit_ste("mem");
      emit_load_src(inst);
      emit_op(OP_REWIND_STR);
      emit_op(OP_SETCURVAR_ARRAY_CREATE);
      emit_op(OP_POP_STK);
      emit_op(OP_LOADVAR_UINT);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(state.register_offset[inst->dst.reg]);
      emit_op(OP_POP_STK);
      break;

    case STORE:
      // mem[src:imm/reg] <- dst:reg
      emit_load_dst(inst);
      emit_op(OP_LOADIMMED_IDENT);
      emit_ste("mem");
      emit_load_src(inst);
      emit_op(OP_REWIND_STR);
      emit_op(OP_SETCURVAR_ARRAY_CREATE);
      emit_op(OP_POP_STK);
      emit_op(OP_SAVEVAR_UINT);
      emit_op(OP_POP_STK);
      break;

    case PUTC:
      // putc(src:imm/reg)
      emit_op(OP_PUSH_FRAME);
      emit_uint(1);
      emit_load_src(inst);
      emit_op(OP_PUSH);
      emit_op(OP_CALLFUNC);
      emit_ste("__putc");
      emit_ste(NULL);
      emit_uint(FunctionCall);
      emit_op(OP_POP_STK);
      break;

    case GETC:
      // dst:reg <- getc()
      emit_op(OP_PUSH_FRAME);
      emit_uint(0);
      emit_op(OP_CALLFUNC);
      emit_ste("__getc");
      emit_ste(NULL);
      emit_uint(FunctionCall);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(state.register_offset[inst->dst.reg]);
      emit_op(OP_POP_STK);
      break;

    case EXIT:
      // return
      emit_op(OP_RETURN_VOID);
      break;

    case DUMP:
      // nop
      break;

    case EQ:
    case NE:
    case LT:
    case GT:
    case LE:
    case GE: {
      // dst:reg <- dst:reg CMP src:imm/reg
      int op;
      switch (inst->op) {
        case EQ: op = OP_CMPEQ; break;
        case NE: op = OP_CMPNE; break;
        case LT: op = OP_CMPLT; break;
        case GT: op = OP_CMPGR; break;
        case LE: op = OP_CMPLE; break;
        case GE: op = OP_CMPGE; break;
        default: assert(false); break;
      }
      emit_load_src(inst);
      emit_load_dst(inst);
      emit_op(op);
      emit_op(OP_SAVE_LOCAL_VAR_UINT);
      emit_op(state.register_offset[inst->dst.reg]);
      emit_op(OP_POP_STK);
      break;
    }
    case JEQ:
    case JNE:
    case JLT:
    case JGT:
    case JLE:
    case JGE: {
      // if (dst:reg CMP src:imm/reg) goto jmp:imm/reg
      int op;
      switch (inst->op) {
        case JEQ: op = OP_CMPEQ; break;
        case JNE: op = OP_CMPNE; break;
        case JLT: op = OP_CMPLT; break;
        case JGT: op = OP_CMPGR; break;
        case JLE: op = OP_CMPLE; break;
        case JGE: op = OP_CMPGE; break;
        default: assert(false); break;
      }
      if (inst->jmp.type == IMM) {
        emit_load_src(inst);
        emit_load_dst(inst);
        emit_op(op);
        emit_op(OP_JMPIF);
        emit_goto(inst->jmp.imm);
      } else {
        emit_op(OP_LOAD_LOCAL_VAR_UINT);
        emit_op(state.register_offset[inst->jmp.reg]);
        emit_load_src(inst);
        emit_load_dst(inst);
        emit_op(op);
        emit_op(OP_JMPIF);
        emit_uint(MAGIC_TRAMPOLINE_ZONE);
      }
      break;
    }

    case JMP:
      // goto jmp:imm/reg
      if (inst->jmp.type == IMM) {
        emit_op(OP_JMP);
        emit_goto(inst->jmp.imm);
      } else {
        emit_op(OP_LOAD_LOCAL_VAR_UINT);
        emit_op(state.register_offset[inst->jmp.reg]);
        emit_op(OP_JMP);
        emit_goto(MAGIC_TRAMPOLINE_ZONE);
      }
      break;

    default:
      break;
    }
  }
  emit_op(OP_RETURN_VOID);

  add_label(MAGIC_TRAMPOLINE_ZONE);

  emit_op(OP_SAVE_LOCAL_VAR_UINT);
  emit_uint(REG_SCRATCH);
  emit_op(OP_POP_STK);

#if DEBUG_SCRIPT
  emit_op(OP_PUSH_FRAME);
  emit_uint(1);
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste("Magic Trampoline Zone! PC <- ");
  emit_op(OP_LOAD_LOCAL_VAR_UINT);
  emit_uint(REG_SCRATCH);
  emit_op(OP_REWIND_STR);
  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("echo");
  emit_ste(NULL);
  emit_op(FunctionCall);
  emit_op(OP_POP_STK);
#endif

  for (Inst* inst = module->text, *last = NULL; inst; last = inst, inst = inst->next) {
    if (!last || last->pc != inst->pc) {
      emit_op(OP_LOAD_LOCAL_VAR_UINT);
      emit_uint(REG_SCRATCH);
      emit_op(OP_LOADIMMED_UINT);
      emit_uint(inst->pc);
      emit_op(OP_CMPEQ);
      emit_op(OP_JMPIF);
      emit_goto(inst->pc);
    }
  }
  emit_op(OP_RETURN_VOID);

  end_func("__main", NULL, NULL, 1, arg_regv, 8);

  start_func(1);

  // if (%c == 10) {
  emit_op(OP_LOAD_LOCAL_VAR_UINT);
  emit_op(arg_regv[0]);
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(10);
  emit_op(OP_CMPEQ);
  emit_op(OP_JMPIFNOT);
  emit_goto(MAGIC_TRAMPOLINE_ZONE + 1);

  // 10:

  // echo($line);
  emit_op(OP_PUSH_FRAME);
  emit_uint(1);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADVAR_STR);
  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("echo");
  emit_ste(NULL);
  emit_op(FunctionCall);
  emit_op(OP_POP_STK);

  // $line = "";
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste("");
  emit_op(OP_SAVEVAR_STR);
  emit_op(OP_POP_STK);
  emit_op(OP_RETURN_VOID);

  // not_10:
  // } else {
  add_label(MAGIC_TRAMPOLINE_ZONE + 1);

  // $line = $line @ chr(%c);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADVAR_STR);

  // chr(%c) {inlined}
  // return getSubStr("etc", %c, 1)
  emit_op(OP_PUSH_FRAME);
  emit_uint(3);
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste(
    " \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff");
  emit_op(OP_PUSH);
  emit_op(OP_LOAD_LOCAL_VAR_UINT);
  emit_op(arg_regv[0]);
  emit_op(OP_PUSH);
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(1);
  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("getSubStr");
  emit_ste(NULL);
  emit_op(FunctionCall);
  emit_op(OP_REWIND_STR);

  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_SAVEVAR_STR);
  emit_op(OP_POP_STK);

  // }
  emit_op(OP_RETURN_VOID);

  end_func("__putc", NULL, NULL, 1, arg_regv, 1);
  /*
  function __putc(%c) {
    if (%c == 10) {
      echo($line);
      $line = "";
    } else {
      $line = $line @ chr(%c);
    }
  }
  // int -> char
  function chr(%i) {
    if (%i == 0) {
      error("Cannot chr(0)!");
      return "";
    }
    return getSubStr(
             " \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        @ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        @ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        @ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
        @ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
        @ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        @ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
        @ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        @ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        @ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        @ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
        @ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        @ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
        @ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
        @ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
        @ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        %i, 1);
  }
  */

  start_func(1);

  // if ($i >= strlen($input)) {

  // strlen($input)
  emit_op(OP_PUSH_FRAME);
  emit_uint(1);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$input");
  emit_op(OP_LOADVAR_STR);
  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("strlen");
  emit_ste(NULL);
  emit_op(FunctionCall);

  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$i");
  emit_op(OP_LOADVAR_UINT);

  emit_op(OP_CMPGE);
  emit_op(OP_JMPIFNOT);
  emit_goto(MAGIC_TRAMPOLINE_ZONE + 2);

  // end:

  // return (-1 & 16777215);
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(UINT_MAX);
  emit_op(OP_RETURN_UINT);
  // }

  // not_end:
  add_label(MAGIC_TRAMPOLINE_ZONE + 2);

  // if ($line !$= "") {
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste("");
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADVAR_STR);
  emit_op(OP_COMPARE_STR);
  emit_op(OP_JMPIF);
  emit_goto(MAGIC_TRAMPOLINE_ZONE + 3);

  // echo($line);
  emit_op(OP_PUSH_FRAME);
  emit_uint(1);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADVAR_STR);
  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("echo");
  emit_ste(NULL);
  emit_op(FunctionCall);
  emit_op(OP_POP_STK);

  // $line = "";
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$line");
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste("");
  emit_op(OP_SAVEVAR_STR);
  emit_op(OP_POP_STK);
  // }

  // after_print:
  add_label(MAGIC_TRAMPOLINE_ZONE + 3);

  // %value = ord(getSubStr($input, $i, 1));

  // ord(that) {inlined}
  // strpos("numbers", that) + 1
  emit_op(OP_PUSH_FRAME);
  emit_uint(2);
  emit_op(OP_LOADIMMED_IDENT);
  emit_ste(
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
    "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff");
  emit_op(OP_PUSH);

  // getSubStr($input, $i, 1)
  emit_op(OP_PUSH_FRAME);
  emit_uint(3);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$input");
  emit_op(OP_LOADVAR_STR);
  emit_op(OP_PUSH);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$i");
  emit_op(OP_LOADVAR_STR);
  emit_op(OP_PUSH);
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(1);
  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("getSubStr");
  emit_ste(NULL);
  emit_op(FunctionCall);

  emit_op(OP_PUSH);
  emit_op(OP_CALLFUNC);
  emit_ste("strpos");
  emit_ste(NULL);
  emit_op(FunctionCall);

  // + 1
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(1);
  emit_op(OP_ADD);

  // $i++;
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$i");
  emit_op(OP_LOADVAR_UINT);
  emit_op(OP_LOADIMMED_UINT);
  emit_uint(1);
  emit_op(OP_ADD);
  emit_op(OP_SETCURVAR_CREATE);
  emit_ste("$i");
  emit_op(OP_SAVEVAR_UINT);
  emit_op(OP_POP_STK);

  // return %value;
  emit_op(OP_RETURN_UINT);

  end_func("__getc", NULL, NULL, 1, arg_regv, 1);
  /*
  function __getc() {
    if ($i >= strlen($input)) {
      return (-1 & 16777215);
    }
    if ($line !$= "") {
      echo($line);
      $line = "";
    }
    %value = ord(getSubStr($input, $i, 1));
    $i++;
    return %value;
  }

  // char -> int
  function ord(%ch) {
    return strpos(
              "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        @ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        @ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        @ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
        @ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
        @ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        @ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
        @ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        @ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        @ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        @ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
        @ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        @ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
        @ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
        @ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
        @ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        %ch) + 1;
  }
  */

  emit_op(OP_RETURN_VOID);

  for (int i = 0; i < state.jmps_size; i ++) {
    int ip = state.jmps[i].ip;
    int pc = state.jmps[i].pc;
    assert(pc < state.labels_cap);
    assert(state.labels[pc] != 0);

    int pc_ip = state.labels[pc];
    state.code[ip] = pc_ip;
#if DEBUG_HOST
    fprintf(stderr, "FIXUP JMP @ %d => %d [%d]\n", ip, pc_ip, pc);
#endif
  }

  emit_le(50); // version
  emit_le(state.global_strings_size); // global strings
  for (int i = 0; i < state.global_strings_size; i ++) {
    emit_1(state.global_strings[i]);
  }
  emit_le(0); // function strings
  emit_le(0); // global floats
  emit_le(0); // function floats
  emit_le(0); // register variable map count

  emit_le(state.code_size); // code count
  emit_le(0); // line break pair count

  for (int i = 0; i < state.code_size; i ++) {
    if (state.code[i] < 0xFF) {
      emit_1(state.code[i]);
    } else {
      emit_1(0xFF);
      emit_le(state.code[i]);
    }
  }

  emit_le(state.stes_size); // identifier count
  for (int i = 0; i < state.stes_size; i ++) {
    emit_le(state.stes[i].index);
    emit_le(1);
    emit_le(state.stes[i].ip);
  }

  // u32 version (50)
  // u32 global strings (0)
  //    u8 chars
  // u32 function strings (0)
  //    u8 chars
  // u32 global floats (0)
  //    f64 float
  // u32 function floats (0)
  //    f64 float
  // u32 register variable map count (0)
  // u32 code count
  // u32 line break pair count (0)
  // [u8 or 0xff u32] code
  // u32 line break pairs (n/a)
  // u32 identifier count (0)
  //    u32 offset in global string table
  //    u32 usage count
  //        u32 ip of usage
}
