// Copyright 2012 Rui Ueyama. Released under the MIT license.

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "8cc.h"

bool dumpstack = false;
bool dumpsource = true;

static int TAB = 8;
static Vector *functions = &EMPTY_VECTOR;
static int stackpos;
#if 0
static int numgp;
static int numfp;
#endif
static FILE *outputfp;
static int is_main;

static Map *source_files = &EMPTY_MAP;
static Map *source_lines = &EMPTY_MAP;
static char *last_loc = "";
static char* current_func_name;

static void emit_addr(Node *node);
static void emit_expr(Node *node);
static void emit_decl_init(Vector *inits, int off, int totalsize);
static void do_emit_data(Vector *inits, int size, int off, int depth);
static void emit_data(Node *v, int off, int depth);

#define REGAREA_SIZE 176

#define emit(...)        emitf(__LINE__, "\t" __VA_ARGS__)
#define emit_noindent(...)  emitf(__LINE__, __VA_ARGS__)

#define assert_float() assert(0 && "float")

#ifdef __eir__
#define MOD24(x) x
#else
#define MOD24(x) (x & 0xffffff)
#endif

#ifdef __GNUC__
#define SAVE                                                            \
    int save_hook __attribute__((unused, cleanup(pop_function)));       \
    if (dumpstack)                                                      \
        vec_push(functions, (void *)__func__);

static void pop_function(void *ignore) {
    if (dumpstack)
        vec_pop(functions);
}
#else
#define SAVE
#endif

static char *get_caller_list() {
    Buffer *b = make_buffer();
    for (int i = 0; i < vec_len(functions); i++) {
        if (i > 0)
            buf_printf(b, " -> ");
        buf_printf(b, "%s", vec_get(functions, i));
    }
    buf_write(b, '\0');
    return buf_body(b);
}

void set_output_file(FILE *fp) {
    outputfp = fp;
}

void close_output_file() {
    fclose(outputfp);
}

static void emitf(int line, char *fmt, ...) {
    // Replace "#" with "%%" so that vfprintf prints out "#" as "%".
    char buf[256];
    int i = 0;
    for (char *p = fmt; *p; p++) {
        assert(i < sizeof(buf) - 3);
        if (*p == '#') {
            buf[i++] = '%';
            buf[i++] = '%';
        } else {
            buf[i++] = *p;
        }
    }
    buf[i] = '\0';

    va_list args;
    va_start(args, fmt);
    int col = vfprintf(outputfp, buf, args);
    va_end(args);

    if (dumpstack) {
        for (char *p = fmt; *p; p++)
            if (*p == '\t')
                col += TAB - 1;
        int space = (28 - col) > 0 ? (30 - col) : 2;
        fprintf(outputfp, "%*c %s:%d", space, '#', get_caller_list(), line);
    }
    fprintf(outputfp, "\n");
}

static void emit_nostack(char *fmt, ...) {
    fprintf(outputfp, "\t");
    va_list args;
    va_start(args, fmt);
    vfprintf(outputfp, fmt, args);
    va_end(args);
    fprintf(outputfp, "\n");
}

static void push(char *reg) {
    SAVE;
    assert(strcmp(reg, "D"));
    emit("mov D, SP");
    emit("add D, -1");
    emit("store %s, D", reg);
    emit("mov SP, D");
    stackpos += 1;
}

static void pop(char *reg) {
    SAVE;
    emit("load %s, SP", reg);
    emit("add SP, 1", reg);
    stackpos -= 1;
    assert(stackpos >= 0);
}

#if 0
static void maybe_emit_bitshift_load(Type *ty) {
    SAVE;
    if (ty->bitsize <= 0)
        return;
    emit("shr $%d, #rax", ty->bitoff);
    push("rcx");
    emit("mov $0x%lx, #rcx", (1 << (long)ty->bitsize) - 1);
    emit("and #rcx, #rax");
    pop("rcx");
}

static void maybe_emit_bitshift_save(Type *ty, char *addr) {
    SAVE;
    if (ty->bitsize <= 0)
        return;
    push("rcx");
    push("rdi");
    emit("mov $0x%lx, #rdi", (1 << (long)ty->bitsize) - 1);
    emit("and #rdi, #rax");
    emit("shl $%d, #rax", ty->bitoff);
    emit("mov %s, #%s", addr, get_int_reg(ty, 'c'));
    emit("mov $0x%lx, #rdi", ~(((1 << (long)ty->bitsize) - 1) << ty->bitoff));
    emit("and #rdi, #rcx");
    emit("or #rcx, #rax");
    pop("rdi");
    pop("rcx");
}
#endif

static void emit_gload(Type *ty, char *label, int off) {
    SAVE;
    if (ty->kind == KIND_ARRAY) {
        emit("mov A, %s", label);
        if (off)
            emit("add A, %d", MOD24(off));
        return;
    }
    emit("mov B, %s", label);
    if (off)
        emit("add B, %d", MOD24(off));
    emit("load A, B");
#if 0
    maybe_emit_bitshift_load(ty);
#endif
}

static void emit_intcast(Type *ty) {
}

static void emit_toint(Type *ty) {
    SAVE;
    if (ty->kind == KIND_FLOAT)
        emit("cvttss2si #xmm0, #eax");
    else if (ty->kind == KIND_DOUBLE)
        emit("cvttsd2si #xmm0, #eax");
}

static void emit_lload(Type *ty, char *base, int off) {
    SAVE;
    if (ty->kind == KIND_ARRAY) {
        emit("mov A, %s", base);
        if (off)
            emit("add A, %d", MOD24(off));
    } else if (ty->kind == KIND_FLOAT) {
        assert_float();
    } else if (ty->kind == KIND_DOUBLE || ty->kind == KIND_LDOUBLE) {
        assert_float();
    } else {
        emit("mov B, %s", base);
        if (off)
            emit("add B, %d", MOD24(off));
        emit("load A, B");
    }
}

static void maybe_convert_bool(Type *ty) {
    if (ty->kind == KIND_BOOL) {
        emit("ne A, 0");
    }
}

static void emit_gsave(char *varname, Type *ty, int off) {
    SAVE;
    assert(ty->kind != KIND_ARRAY);
    maybe_convert_bool(ty);
#if 0
    char *reg = get_int_reg(ty, 'a');
    char *addr = format("%s+%d(%%rip)", varname, off);
    maybe_emit_bitshift_save(ty, addr);
#endif
    emit("mov B, %s", varname);
    if (off)
        emit("add B, %d", MOD24(off));
    emit("store A, B");
}

static void emit_lsave(Type *ty, int off) {
    SAVE;
    if (ty->kind == KIND_FLOAT) {
        assert_float();
    } else if (ty->kind == KIND_DOUBLE) {
        assert_float();
    } else {
        emit("mov B, BP");
        if (off)
            emit("add B, %d", MOD24(off));
        emit("store A, B");
    }
}

static void do_emit_assign_deref(Type *ty, int off) {
    SAVE;
    emit("mov C, A");
    emit("load A, SP");
    emit("mov B, A");
    emit("mov A, C");
    if (off)
        emit("add A, %d", MOD24(off));
    emit("store B, A");
    pop("A");
}

static void emit_assign_deref(Node *var) {
    SAVE;
    push("A");
    emit_expr(var->operand);
    do_emit_assign_deref(var->operand->ty->ptr, 0);
}

static void emit_call_builtin(char *fname);

static void emit_pointer_arith(char kind, Node *left, Node *right) {
    SAVE;
    emit_expr(left);
    push("B");
    push("A");
    emit_expr(right);

    if (left->ty->ptr->size == 2)
        emit("add A, A");
    if (left->ty->ptr->size > 2) {
        push("A");
        emit("mov A, %d", left->ty->ptr->size);
        push("A");
        emit_call_builtin("__builtin_mul");
        emit("add SP, 2");
        stackpos -= 3;
    }

    emit("mov B, A");
    pop("A");
    switch (kind) {
    case '+': emit("add A, B"); break;
    case '-': emit("sub A, B"); break;
    default: error("invalid operator '%d'", kind);
    }
    emit("mov C, A");
    pop("A");
    emit("mov B, A");
    emit("mov A, C");
}

static void emit_zero_filler(int start, int end) {
    SAVE;
    emit("mov A, 0");
    emit("mov B, SP");
    for (; start != end; start++) {
        emit("store A, B");
        emit("add B, 1");
    }
}

static void ensure_lvar_init(Node *node) {
    SAVE;
    assert(node->kind == AST_LVAR);
    if (node->lvarinit)
        emit_decl_init(node->lvarinit, node->loff, node->ty->size);
    node->lvarinit = NULL;
}

static void emit_assign_struct_ref(Node *struc, Type *field, int off) {
    SAVE;
    switch (struc->kind) {
    case AST_LVAR:
        ensure_lvar_init(struc);
        emit_lsave(field, struc->loff + field->offset + off);
        break;
    case AST_GVAR:
        emit_gsave(struc->glabel, field, field->offset + off);
        break;
    case AST_STRUCT_REF:
        emit_assign_struct_ref(struc->struc, field, off + struc->ty->offset);
        break;
    case AST_DEREF:
        push("A");
        emit_expr(struc->operand);
        do_emit_assign_deref(field, field->offset + off);
        break;
    default:
        error("internal error: %s", node2s(struc));
    }
}

static void emit_load_struct_ref(Node *struc, Type *field, int off) {
    SAVE;
    switch (struc->kind) {
    case AST_LVAR:
        ensure_lvar_init(struc);
        emit_lload(field, "BP", struc->loff + field->offset + off);
        break;
    case AST_GVAR:
        emit_gload(field, struc->glabel, field->offset + off);
        break;
    case AST_STRUCT_REF:
        emit_load_struct_ref(struc->struc, field, struc->ty->offset + off);
        break;
    case AST_DEREF:
        emit_expr(struc->operand);
        emit_lload(field, "A", field->offset + off);
        break;
    default:
        error("internal error: %s", node2s(struc));
    }
}

static void emit_store(Node *var) {
    SAVE;
    switch (var->kind) {
    case AST_DEREF: emit_assign_deref(var); break;
    case AST_STRUCT_REF: emit_assign_struct_ref(var->struc, var->ty, 0); break;
    case AST_LVAR:
        ensure_lvar_init(var);
        emit_lsave(var->ty, var->loff);
        break;
    case AST_GVAR: emit_gsave(var->glabel, var->ty, 0); break;
    default: error("internal error");
    }
}

static void emit_to_bool(Type *ty) {
    SAVE;
    if (is_flotype(ty)) {
        assert_float();
    } else {
        emit("ne A, 0");
    }
}

static void emit_comp(char *inst, Node *node) {
    SAVE;
    if (is_flotype(node->left->ty)) {
        assert_float();
    } else {
        emit_expr(node->left);
        push("A");
        emit_expr(node->right);
        emit("mov B, A");
        pop("A");
    }
    emit("%s A, B", inst);
}

static void emit_binop_int_arith(Node *node) {
    SAVE;
    emit_expr(node->left);
    push("A");
    emit_expr(node->right);
    emit("mov B, A");
    pop("A");
    switch (node->kind) {
        case '+':
            emit("add A, B");
            break;
        case '-':
            emit("sub A, B");
            break;
        case '*':
        case '/':
        case '%':
        case '^':
        case OP_SAL:
        case OP_SAR:
        case OP_SHR:
            push("B");
            push("A");
            if (node->kind == '*')
                emit_call_builtin("__builtin_mul");
            else if (node->kind == '/')
                emit_call_builtin("__builtin_div");
            else if (node->kind == '%')
                emit_call_builtin("__builtin_mod");
            else if (node->kind == '^')
                emit_call_builtin("__builtin_xor");
            else if (node->kind == OP_SAL)
                emit_call_builtin("__builtin_shl");
            else if (node->kind == OP_SAR || node->kind == OP_SHR)
                emit_call_builtin("__builtin_shr");
            emit("add SP, 2");
            stackpos -= 3;
            break;
        default: error("invalid operator '%d'", node->kind);
    }
}

static void emit_binop_float_arith(Node *node) {
    SAVE;
    assert_float();
}

static void emit_load_convert(Type *to, Type *from) {
    SAVE;
    if (is_inttype(from) && to->kind == KIND_FLOAT)
        emit("cvtsi2ss #eax, #xmm0");
    else if (is_inttype(from) && to->kind == KIND_DOUBLE)
        emit("cvtsi2sd #eax, #xmm0");
    else if (from->kind == KIND_FLOAT && to->kind == KIND_DOUBLE)
        emit("cvtps2pd #xmm0, #xmm0");
    else if ((from->kind == KIND_DOUBLE || from->kind == KIND_LDOUBLE) && to->kind == KIND_FLOAT)
        emit("cvtpd2ps #xmm0, #xmm0");
    else if (to->kind == KIND_BOOL)
        emit_to_bool(from);
    else if (is_inttype(from) && is_inttype(to))
        emit_intcast(from);
    else if (is_inttype(to))
        emit_toint(from);
}

static void emit_ret() {
    SAVE;
    emit_nostack("#{pop:%s}", current_func_name);
    if (is_main) {
        emit("exit");
    } else {
        emit("mov SP, BP");
        pop("A");
        emit("mov BP, A");
        pop("A");
        emit("jmp A");
        stackpos += 2;
    }
}

static void emit_binop(Node *node) {
    SAVE;
    if (node->ty->kind == KIND_PTR) {
        emit_pointer_arith(node->kind, node->left, node->right);
        return;
    }
    switch (node->kind) {
    case '<': emit_comp("lt", node); return;
    case OP_EQ: emit_comp("eq", node); return;
    case OP_LE: emit_comp("le", node); return;
    case OP_NE: emit_comp("ne", node); return;
    }
    if (is_inttype(node->ty))
        emit_binop_int_arith(node);
    else if (is_flotype(node->ty))
        emit_binop_float_arith(node);
    else
        error("internal error: %s", node2s(node));
}

static void emit_save_literal(Node *node, Type *totype, int off) {
    int v = node->ival;
    switch (totype->kind) {
    case KIND_BOOL:
        v = !!v;
    case KIND_CHAR:
    case KIND_SHORT:
    case KIND_INT:
    case KIND_LONG:
    case KIND_LLONG:
    case KIND_PTR: {
        emit("mov B, BP");
        if (off)
            emit("add B, %d", MOD24(off));
        emit("mov A, %d", MOD24(v));
        emit("store A, B");
        break;
    }
    case KIND_FLOAT:
    case KIND_DOUBLE:
        assert_float();
    default:
        error("internal error: <%s> <%s> <%d>", node2s(node), ty2s(totype), off);
    }
}

static void emit_addr(Node *node) {
    switch (node->kind) {
    case AST_LVAR:
        ensure_lvar_init(node);
        emit("mov A, BP");
        emit("add A, %d", node->loff);
        break;
    case AST_GVAR:
        emit("mov A, %s", node->glabel);
        break;
    case AST_DEREF:
        emit_expr(node->operand);
        break;
    case AST_STRUCT_REF:
        emit_addr(node->struc);
        emit("add A, %d", node->ty->offset);
        break;
    case AST_FUNCDESG:
        emit("mov A, %s", node->fname);
        break;
    default:
        error("internal error: %s", node2s(node));
    }
}

static void emit_copy_struct(Node *left, Node *right) {
    push("B");
    push("C");
    emit_addr(right);
    push("A");
    emit_addr(left);
    emit("mov C, A");
    pop("A");
    emit("mov B, A");
    int i = 0;
    for (; i < left->ty->size; i++) {
        emit("load A, B");
        emit("store A, C");
        emit("add B, 1");
        emit("add C, 1");
    }
    pop("A");
    emit("mov C, A");
    pop("A");
    emit("mov B, A");
}

static int cmpinit(const void *x, const void *y) {
    Node *a = *(Node **)x;
    Node *b = *(Node **)y;
    return a->initoff - b->initoff;
}

static void emit_fill_holes(Vector *inits, int off, int totalsize) {
    // If at least one of the fields in a variable are initialized,
    // unspecified fields has to be initialized with 0.
    int len = vec_len(inits);
    Node **buf = malloc(len * sizeof(Node *));
    for (int i = 0; i < len; i++)
        buf[i] = vec_get(inits, i);
    qsort(buf, len, sizeof(Node *), cmpinit);

    int lastend = 0;
    for (int i = 0; i < len; i++) {
        Node *node = buf[i];
        if (lastend < node->initoff)
            emit_zero_filler(lastend + off, node->initoff + off);
        lastend = node->initoff + node->totype->size;
    }
    emit_zero_filler(lastend + off, totalsize + off);
}

static void emit_decl_init(Vector *inits, int off, int totalsize) {
    emit_fill_holes(inits, off, totalsize);
    for (int i = 0; i < vec_len(inits); i++) {
        Node *node = vec_get(inits, i);
        assert(node->kind == AST_INIT);
        bool isbitfield = (node->totype->bitsize > 0);
        if (node->initval->kind == AST_LITERAL && !isbitfield) {
            emit_save_literal(node->initval, node->totype, node->initoff + off);
        } else {
            emit_expr(node->initval);
            emit_lsave(node->totype, node->initoff + off);
        }
    }
}

static void emit_pre_inc_dec(Node *node, char *op) {
    emit_expr(node->operand);
    emit("%s A, 1", op);
    emit_store(node->operand);
}

static void emit_post_inc_dec(Node *node, char *op) {
    SAVE;
    emit_expr(node->operand);
    push("A");
    emit("%s A, 1", op);
    emit_store(node->operand);
    pop("A");
}

static void emit_je(char *label) {
    emit("jeq %s, A, 0", label);
}

static void emit_label(char *label) {
    emit("%s:", label);
}

static void emit_jmp(char *label) {
    emit("jmp %s", label);
}

static void emit_call_builtin(char *fname) {
    char *end = make_label();
    emit("mov A, %s", end);
    push("A");
    emit("jmp %s", fname);
    emit_label(end);
    emit("mov A, B");
}

static void emit_literal(Node *node) {
    SAVE;
    switch (node->ty->kind) {
    case KIND_BOOL:
    case KIND_CHAR:
    case KIND_SHORT:
        emit("mov A, %d", MOD24(node->ival));
        break;
    case KIND_INT:
    case KIND_LONG:
    case KIND_LLONG: {
        emit("mov A, %d", MOD24(node->ival));
        break;
    }
    case KIND_FLOAT:
    case KIND_DOUBLE:
    case KIND_LDOUBLE: {
        assert_float();
        break;
    }
    case KIND_ARRAY: {
        if (!node->slabel) {
            node->slabel = make_label();
            emit_noindent(".data");
            emit_label(node->slabel);
            emit(".string \"%s\"", quote_cstring_len(node->sval, node->ty->size - 1));
            emit_noindent(".text");
        }
        emit("mov A, %s", node->slabel);
        break;
    }
    default:
        error("internal error");
    }
}

static char **split(char *buf) {
    char *p = buf;
    int len = 1;
    while (*p) {
        if (p[0] == '\r' && p[1] == '\n') {
            len++;
            p += 2;
            continue;
        }
        if (p[0] == '\r' || p[0] == '\n')
            len++;
        p++;
    }
    p = buf;
    char **r = malloc(sizeof(char *) * len + 1);
    int i = 0;
    while (*p) {
        if (p[0] == '\r' && p[1] == '\n') {
            p[0] = '\0';
            p += 2;
            r[i++] = p;
            continue;
        }
        if (p[0] == '\r' || p[0] == '\n') {
            p[0] = '\0';
            r[i++] = p + 1;
        }
        p++;
    }
    r[i] = NULL;
    return r;
}

#ifndef __eir__
static char **read_source_file(char *file) {
    FILE *fp = fopen(file, "r");
    if (!fp)
        return NULL;
    struct stat st;
    fstat(fileno(fp), &st);
    char *buf = malloc(st.st_size + 1);
    if (fread(buf, 1, st.st_size, fp) != st.st_size)
        return NULL;
    fclose(fp);
    buf[st.st_size] = '\0';
    return split(buf);
}
#endif

static void maybe_print_source_line(char *file, int line) {
    if (!dumpsource)
        return;
    char **lines = map_get(source_lines, file);
    if (!lines) {
#ifdef __eir__
        return;
#else
        lines = read_source_file(file);
        if (!lines)
            return;
        map_put(source_lines, file, lines);
#endif
    }
    int len = 0;
    for (char **p = lines; *p; p++)
        len++;
    emit_nostack("# %s", lines[line - 1]);
}

static void maybe_print_source_loc(Node *node) {
    if (!node->sourceLoc)
        return;
    char *file = node->sourceLoc->file;
    long fileno = (long)map_get(source_files, file);
    if (!fileno) {
        fileno = map_len(source_files) + 1;
        map_put(source_files, file, (void *)fileno);
        emit(".file %ld \"%s\"", fileno, quote_cstring(file));
    }
    char *loc = format(".loc %ld %d 0", fileno, node->sourceLoc->line);
    if (strcmp(loc, last_loc)) {
        emit("%s", loc);
        maybe_print_source_line(file, node->sourceLoc->line);
    }
    last_loc = loc;
}

static void emit_lvar(Node *node) {
    SAVE;
    ensure_lvar_init(node);
    emit_lload(node->ty, "BP", node->loff);
}

static void emit_gvar(Node *node) {
    SAVE;
    emit_gload(node->ty, node->glabel, 0);
}

#if 0

static void emit_builtin_return_address(Node *node) {
    push("r11");
    assert(vec_len(node->args) == 1);
    emit_expr(vec_head(node->args));
    char *loop = make_label();
    char *end = make_label();
    emit("mov #rbp, #r11");
    emit_label(loop);
    emit("test #rax, #rax");
    emit("jz %s", end);
    emit("mov (#r11), #r11");
    emit("sub $1, #rax");
    emit_jmp(loop);
    emit_label(end);
    emit("mov 8(#r11), #rax");
    pop("r11");
}

// Set the register class for parameter passing to RAX.
// 0 is INTEGER, 1 is SSE, 2 is MEMORY.
static void emit_builtin_reg_class(Node *node) {
    Node *arg = vec_get(node->args, 0);
    assert(arg->ty->kind == KIND_PTR);
    Type *ty = arg->ty->ptr;
    if (ty->kind == KIND_STRUCT)
        emit("mov $2, #eax");
    else if (is_flotype(ty))
        emit("mov $1, #eax");
    else
        emit("mov $0, #eax");
}

static void emit_builtin_va_start(Node *node) {
    SAVE;
    assert(vec_len(node->args) == 1);
    emit_expr(vec_head(node->args));
    push("rcx");
    emit("movl $%d, (#rax)", numgp * 8);
    emit("movl $%d, 4(#rax)", 48 + numfp * 16);
    emit("lea %d(#rbp), #rcx", -REGAREA_SIZE);
    emit("mov #rcx, 16(#rax)");
    pop("rcx");
}

#endif

static bool maybe_emit_builtin(Node *node) {
#if 0
    SAVE;
    if (!strcmp("__builtin_return_address", node->fname)) {
        emit_builtin_return_address(node);
        return true;
    }
    if (!strcmp("__builtin_reg_class", node->fname)) {
        emit_builtin_reg_class(node);
        return true;
    }
    if (!strcmp("__builtin_va_start", node->fname)) {
        emit_builtin_va_start(node);
        return true;
    }
    return false;
#else
    return false;
#endif
}

static void classify_args(Vector *ints, Vector *args) {
    SAVE;
    for (int i = 0; i < vec_len(args); i++) {
        Node *v = vec_get(args, i);
        assert(!is_flotype(v->ty));
        vec_push(ints, v);
    }
}

static int emit_args(Vector *vals) {
    SAVE;
    int r = 0;
    for (int i = 0; i < vec_len(vals); i++) {
        Node *v = vec_get(vals, i);
        emit_expr(v);
        push("A");
        r += 1;
    }
    return r;
}

static void maybe_booleanize_retval(Type *ty) {
    if (ty->kind == KIND_BOOL) {
        emit("ne A, 0");
    }
}

static void emit_call(Node *node) {
    bool isptr = (node->kind == AST_FUNCPTR_CALL);
    char *end = make_label();
    if (isptr) {
        emit_expr(node->fptr);
        emit("mov C, A");
    }
    emit("mov A, %s", end);
    push("A");
    if (isptr)
        emit("jmp C");
    else
        emit("jmp %s", node->fname);
    emit_label(end);
    emit("mov A, B");
    stackpos -= 1;
}

static void emit_func_call(Node *node) {
    SAVE;
    int opos = stackpos;

    Vector *ints = make_vector();
    classify_args(ints, node->args);

    emit_args(vec_reverse(ints));

    if (!node->fname) {
        emit_call(node);
    } else if (!strcmp(node->fname, "__builtin_dump")) {
        emit("dump");
    } else if (!strcmp(node->fname, "exit")) {
        emit("exit");
    } else if (!strcmp(node->fname, "putchar")) {
        emit("putc A");
    } else if (!strcmp(node->fname, "getchar")) {
        char *end = make_label();
        emit("getc A");
        emit("jne %s, A, 0", end);
        emit("mov A, -1");
        emit_label(end);
    } else {
        emit_call(node);
    }
    if (vec_len(ints))
        emit("add SP, %d", vec_len(ints));
    stackpos -= vec_len(ints);
    assert(opos == stackpos);
}

static void emit_decl(Node *node) {
    SAVE;
    if (!node->declinit)
        return;
    emit_decl_init(node->declinit, node->declvar->loff, node->declvar->ty->size);
}

static void emit_conv(Node *node) {
    SAVE;
    emit_expr(node->operand);
    emit_load_convert(node->ty, node->operand->ty);
}

static void emit_deref(Node *node) {
    SAVE;
    emit_expr(node->operand);
    emit_lload(node->operand->ty->ptr, "A", 0);
    emit_load_convert(node->ty, node->operand->ty->ptr);
}

static void emit_ternary(Node *node) {
    SAVE;
    emit_expr(node->cond);
    char *ne = make_label();
    emit_je(ne);
    if (node->then)
        emit_expr(node->then);
    if (node->els) {
        char *end = make_label();
        emit_jmp(end);
        emit_label(ne);
        emit_expr(node->els);
        emit_label(end);
    } else {
        emit_label(ne);
    }
}

static void emit_goto(Node *node) {
    SAVE;
    assert(node->newlabel);
    emit_jmp(node->newlabel);
}

static void emit_return(Node *node) {
    SAVE;
    if (node->retval) {
        emit_expr(node->retval);
        maybe_booleanize_retval(node->retval->ty);
        emit("mov B, A");
    }
    emit_ret();
}

static void emit_compound_stmt(Node *node) {
    SAVE;
    for (int i = 0; i < vec_len(node->stmts); i++)
        emit_expr(vec_get(node->stmts, i));
}

static void emit_logand(Node *node) {
    SAVE;
    char *end = make_label();
    emit_expr(node->left);
    emit("mov B, 0");
    emit("jeq %s, A, 0", end);
    emit_expr(node->right);
    emit("mov B, A");
    emit("ne B, 0");
    emit_label(end);
    emit("mov A, B");
}

static void emit_logor(Node *node) {
    SAVE;
    char *end = make_label();
    emit_expr(node->left);
    emit("mov B, 1");
    emit("jne %s, A, 0", end);
    emit_expr(node->right);
    emit("mov B, A");
    emit("ne B, 0");
    emit_label(end);
    emit("mov A, B");
}

static void emit_lognot(Node *node) {
    SAVE;
    emit_expr(node->operand);
    emit("eq A, 0");
}

static void emit_bitand(Node *node) {
    SAVE;
    emit_expr(node->left);
    push("A");
    emit_expr(node->right);
    push("A");
    emit_call_builtin("__builtin_and");
    emit("add SP, 2");
    stackpos -= 3;
}

static void emit_bitor(Node *node) {
    SAVE;
    emit_expr(node->left);
    push("A");
    emit_expr(node->right);
    push("A");
    emit_call_builtin("__builtin_or");
    emit("add SP, 2");
    stackpos -= 3;
}

static void emit_bitnot(Node *node) {
    SAVE;
    emit_expr(node->left);
    push("A");
    emit_call_builtin("__builtin_not");
    emit("add SP, 1");
    stackpos -= 2;
}

static void emit_cast(Node *node) {
    SAVE;
    emit_expr(node->operand);
    emit_load_convert(node->ty, node->operand->ty);
    return;
}

static void emit_comma(Node *node) {
    SAVE;
    emit_expr(node->left);
    emit_expr(node->right);
}

static void emit_assign(Node *node) {
    SAVE;
    if (node->left->ty->kind == KIND_STRUCT) {
        emit_copy_struct(node->left, node->right);
    } else {
        emit_expr(node->right);
        emit_load_convert(node->ty, node->right->ty);
        emit_store(node->left);
    }
}

static void emit_label_addr(Node *node) {
    SAVE;
    emit("mov A, %s", node->newlabel);
}

static void emit_computed_goto(Node *node) {
    SAVE;
    emit_expr(node->operand);
    emit("jmp A");
}

static void emit_expr(Node *node) {
    SAVE;
    maybe_print_source_loc(node);
    switch (node->kind) {
    case AST_LITERAL: emit_literal(node); return;
    case AST_LVAR:    emit_lvar(node); return;
    case AST_GVAR:    emit_gvar(node); return;
    case AST_FUNCDESG: emit_addr(node); return;
    case AST_FUNCALL:
        if (maybe_emit_builtin(node))
            return;
        // fall through
    case AST_FUNCPTR_CALL:
        emit_func_call(node);
        return;
    case AST_DECL:    emit_decl(node); return;
    case AST_CONV:    emit_conv(node); return;
    case AST_ADDR:    emit_addr(node->operand); return;
    case AST_DEREF:   emit_deref(node); return;
    case AST_IF:
    case AST_TERNARY:
        emit_ternary(node);
        return;
    case AST_GOTO:    emit_goto(node); return;
    case AST_LABEL:
        if (node->newlabel)
            emit_label(node->newlabel);
        return;
    case AST_RETURN:  emit_return(node); return;
    case AST_COMPOUND_STMT: emit_compound_stmt(node); return;
    case AST_STRUCT_REF:
        emit_load_struct_ref(node->struc, node->ty, 0);
        return;
    case OP_PRE_INC:   emit_pre_inc_dec(node, "add"); return;
    case OP_PRE_DEC:   emit_pre_inc_dec(node, "sub"); return;
    case OP_POST_INC:  emit_post_inc_dec(node, "add"); return;
    case OP_POST_DEC:  emit_post_inc_dec(node, "sub"); return;
    case '!': emit_lognot(node); return;
    case '&': emit_bitand(node); return;
    case '|': emit_bitor(node); return;
    case '~': emit_bitnot(node); return;
    case OP_LOGAND: emit_logand(node); return;
    case OP_LOGOR:  emit_logor(node); return;
    case OP_CAST:   emit_cast(node); return;
    case ',': emit_comma(node); return;
    case '=': emit_assign(node); return;
    case OP_LABEL_ADDR: emit_label_addr(node); return;
    case AST_COMPUTED_GOTO: emit_computed_goto(node); return;
    default:
        emit_binop(node);
    }
}

static void emit_zero(int size) {
    SAVE;
    if (size == -1)
        return;
    for (; size > 0; size--)     emit(".long 0");
}

static void emit_padding(Node *node, int off) {
    SAVE;
    int diff = node->initoff - off;
    assert(diff >= 0);
    emit_zero(diff);
}

static void emit_data_addr(Node *operand, int depth) {
    switch (operand->kind) {
    case AST_LVAR: {
        char *label = make_label();
        emit(".data %d", depth + 1);
        emit_label(label);
        do_emit_data(operand->lvarinit, operand->ty->size, 0, depth + 1);
        emit(".data %d", depth);
        emit(".long %s", label);
        return;
    }
    case AST_GVAR:
        emit(".long %s", operand->glabel);
        return;
    default:
        error("internal error");
    }
}

static void emit_data_charptr(char *s, int depth) {
    char *label = make_label();
    emit(".data %d", depth + 1);
    emit_label(label);
    emit(".string \"%s\"", quote_cstring(s));
    emit(".data %d", depth);
    emit(".long %s", label);
}

static void emit_data_primtype(Type *ty, Node *val, int depth) {
    switch (ty->kind) {
    case KIND_FLOAT: {
        assert_float();
        break;
    }
    case KIND_DOUBLE:
        assert_float();
        break;
    case KIND_BOOL:
        emit(".long %d", !!eval_intexpr(val, NULL));
        break;
    case KIND_CHAR:
    case KIND_SHORT:
    case KIND_INT:
        emit(".long %d", eval_intexpr(val, NULL));
        break;
    case KIND_LONG:
    case KIND_LLONG:
    case KIND_PTR:
        if (val->kind == OP_LABEL_ADDR) {
            emit(".long %s", val->newlabel);
            break;
        }
        bool is_char_ptr = (val->operand->ty->kind == KIND_ARRAY && val->operand->ty->ptr->kind == KIND_CHAR);
        if (is_char_ptr) {
            emit_data_charptr(val->operand->sval, depth);
        } else if (val->kind == AST_GVAR) {
            emit(".long %s", val->glabel);
        } else {
            Node *base = NULL;
            int v = eval_intexpr(val, &base);
            if (base == NULL) {
                emit(".long %u", v);
                break;
            }
            Type *ty = base->ty;
            if (base->kind == AST_CONV || base->kind == AST_ADDR)
                base = base->operand;
            if (base->kind != AST_GVAR)
                error("global variable expected, but got %s", node2s(base));
            assert(ty->ptr);
#if 1
            if (v * ty->ptr->size)
                error("TODO: fix! %d %d", v, ty->ptr->size);
            emit(".long %s", base->glabel);
#else
            emit(".long %s+%u", base->glabel, v * ty->ptr->size);
#endif
        }
        break;
    default:
        error("don't know how to handle\n  <%s>\n  <%s>", ty2s(ty), node2s(val));
    }
}

static void do_emit_data(Vector *inits, int size, int off, int depth) {
    SAVE;
    for (int i = 0; i < vec_len(inits) && 0 < size && size != -1; i++) {
        Node *node = vec_get(inits, i);
        Node *v = node->initval;
        emit_padding(node, off);
        // TODO: Fix!
        //if (node->totype->bitsize > 0 && node->totype->bitsize != -1) {
        if (0) {
            assert(node->totype->bitoff == 0);
            long data = eval_intexpr(v, NULL);
            Type *totype = node->totype;
            for (i++ ; i < vec_len(inits); i++) {
                node = vec_get(inits, i);
                if (node->totype->bitsize <= 0) {
                    break;
                }
                v = node->initval;
                totype = node->totype;
                data |= ((((long)1 << totype->bitsize) - 1) & eval_intexpr(v, NULL)) << totype->bitoff;
            }
            emit_data_primtype(totype, &(Node){ AST_LITERAL, totype, .ival = data }, depth);
            off += totype->size;
            size -= totype->size;
            if (i == vec_len(inits))
                break;
        } else {
            off += node->totype->size;
            size -= node->totype->size;
        }
        if (v->kind == AST_ADDR) {
            emit_data_addr(v->operand, depth);
            continue;
        }
        if (v->kind == AST_LVAR && v->lvarinit) {
            do_emit_data(v->lvarinit, v->ty->size, 0, depth);
            continue;
        }
        emit_data_primtype(node->totype, node->initval, depth);
    }
    emit_zero(size);
}

static void emit_data(Node *v, int off, int depth) {
    SAVE;
    emit(".data %d", depth);
#if 0
    if (!v->declvar->ty->isstatic)
        emit_noindent(".global %s", v->declvar->glabel);
#endif
    emit_noindent("%s:", v->declvar->glabel);
    do_emit_data(v->declinit, v->declvar->ty->size, off, depth);
}

static void emit_bss(Node *v) {
    SAVE;
    emit(".data");
#if 0
    if (!v->declvar->ty->isstatic)
        emit(".global %s", v->declvar->glabel);
    emit(".lcomm %s, %d", v->declvar->glabel, v->declvar->ty->size);
#else
    int i;
    emit("%s:\n", v->declvar->glabel);
    for (i = 0; i < v->declvar->ty->size && v->declvar->ty->size != -1; i++) {
      emit(".long 0");
    }
#endif
}

static void emit_global_var(Node *v) {
    SAVE;
    if (v->declinit)
        emit_data(v, 0, 0);
    else
        emit_bss(v);
}

static void assign_func_param_offsets(Vector *params, int off) {
    int arg = 2;
    for (int i = 0; i < vec_len(params); i++) {
        Node *v = vec_get(params, i);
        if (is_flotype(v->ty))
            assert_float();
        v->loff = arg++;
    }
}

static void emit_func_prologue(Node *func) {
    SAVE;
    emit(".text");
    emit_noindent("%s:", func->fname);
    current_func_name = func->fname;
    emit_nostack("#{push:%s}", func->fname);

    push("BP");
    emit("mov BP, SP");
    int off = 0;
    assign_func_param_offsets(func->params, off);

    int localarea = 0;
    for (int i = 0; i < vec_len(func->localvars); i++) {
        Node *v = vec_get(func->localvars, i);
        int size = v->ty->size;
        off -= size;
        v->loff = off;
        localarea += size;
    }
    if (localarea) {
        emit("sub SP, %d", localarea);
        stackpos += localarea;
    }
}

void emit_toplevel(Node *v) {
    stackpos = 1;
    if (v->kind == AST_FUNC) {
        is_main = !strcmp(v->fname, "main");
        emit_func_prologue(v);
        emit_expr(v->body);
        emit_ret();
        is_main = 0;
    } else if (v->kind == AST_DECL) {
        emit_global_var(v);
    } else {
        error("internal error");
    }
}
