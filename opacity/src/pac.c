#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include<signal.h>
#include <sys/prctl.h>

//#define DEBUG  1
//#define USE_RING 1
#define COMPRESSED_PTRS 1
//#define PRODUCE_CODE 1
//#define DEBUG_CPU 1
//#define VERBOSE_RING 1
//#define VERBOSE_STACK 1
//#define VERBOSE_MEMORY 1
//#define VERBOSE_RESET 1
//#define VERBOSE_PROCESS 1
//#define VERBOSE_GATE_CREATION 1
//#define VERBOSE_GATE_EVAL 1
//#define VERBOSE_IO 1
//#define VERBOSE_ALLOC 1
//#define VERBOSE_CLOCK_CYCLE
//#define VERBOSE_PLACEHOLDERS 1
//#define INCLUDE_INST_DECODE 1
//#define ASSERT_HINTS 1
//#define TEST_HINTS 1
//#define SOL_DUMP
// Swap the order of bits between programs making the challenge harder
//#define SWAP_INST_BITS 1
// Each program gets its own random seed
//#define PROG_RAND 1
//
//

#ifdef TEST_HINTS
#define thputs puts
#define thprintf printf
#else
#define thputs(...)
#define thprintf(...)
#endif

#ifdef PRODUCE_CODE
#define DEBUG_ASSERT  1
#define INCLUDE_INST_DECODE 1
//#define VERBOSE_GATE_CREATION 1
#endif

#ifdef DEBUG_ASSERT
#include <assert.h>
#define assert_m(cond, m) assert(cond)
#define assert_h(cond, m) assert(cond)

#else
void assert(int cond) {
    if (!(cond)) {
        puts("ASSERTION FAILED");
        exit(-1);
        abort();
    }
}
void assert_m(int cond, char* msg) {
    if (!(cond)) {
        printf("ASSERTION FAILED: %s\n", msg);
        exit(-1);
        abort();
    }
}
#ifdef ASSERT_HINTS
#define assert_h assert_m
#else
#define assert_h(cond, m) assert(cond)
#endif
#endif

time_t g_start_t = 0;

// https://github.com/microsoft/checkedc-llvm/blob/master/test/MC/AArch64/armv8.3a-signed-pointer.s
uint64_t inline __attribute__((always_inline)) pac_sign(uint64_t val, uint64_t ctx) {
    uint64_t out = 0;
    asm(
        "mov x17, %1;"
        "mov x16, %2;"
        ".byte 0x5f;"
        ".byte 0x21;"
        ".byte 0x03;"
        ".byte 0xd5;"
        "mov %0, x17;"
        : "=r"(out)
        : "r"(val), "r"(ctx)
        : "x17", "x16"
    );
    return out;
}

uint64_t inline __attribute__((always_inline)) pac_verify(uint64_t val, uint64_t ctx) {
    uint64_t out = 0;
    asm(
        "mov x17, %1;"
        "mov x16, %2;"
        ".byte 0xdf;"
        ".byte 0x21;"
        ".byte 0x03;"
        ".byte 0xd5;"
        "mov %0, x17;"
        : "=r"(out)
        : "r"(val), "r"(ctx)
        : "x17", "x16"
    );
    return out;
}

int inline __attribute__((always_inline)) pac_gate_res(uint16_t code, uint64_t val, uint64_t ctx) {
    uint64_t c = code;
    val = pac_verify((c << 48) | val, ctx);
    if ((val >> 48) == 0)
        return 0;
    return 1;
}

void reset_pac() {
    prctl(PR_PAC_RESET_KEYS, PR_PAC_APIBKEY, 0,0,0);
}

/*
The gate acts as an and/nand gate
Ptr | Ctx | Code
 1  |  1  |  0
 0  |  1  |  1
 1  |  0  |  1
 0  |  0  |  1
*/


typedef enum GateType {
    g_NAND,
    g_SET,
    g_NOT,
    g_INPUT,
    g_OUTPUT,
    g_MEMORY,
    g_PLACEHOLDER, // Used to form back connections
} GateType;

typedef enum GateFlags {
    f_UNINIT = 1,
    f_SANITY = 2,
    f_SANITY_DECODE = 4,
} GateFlags;

#define HAS_FLAG(g, f) ((g->flags & f) != 0)
#define SET_FLAG(g, f, v) if (v) { g->flags |= f; } else { g->flags &= ~f; }


#ifdef COMPRESSED_PTRS
typedef uint32_t GateHeapPtr;
#define P(off) ((Gate*)((uint64_t)(off)))
#define O(ptr) ((uint32_t)((uint64_t)(ptr)))
#else
typedef Gate* GateHeapPtr;
#define P(off) (off)
#define O(ptr) (ptr)
#endif

typedef struct gate Gate;
struct gate {
    uint8_t type : 3;
    uint8_t flags : 5;
    uint8_t salt;
    uint16_t code;
    GateHeapPtr in_a;
    GateHeapPtr in_b;
    uint32_t t_v;
    uint32_t f_v;

    // Runtime
    uint32_t res;
    GateHeapPtr out;
#if DEBUG 
    char* name;
#endif
};

typedef struct gateset {
    uint8_t type : 3;
    uint8_t flags : 5;
    Gate* parent;
    Gate** children;
    uint64_t alloc_size;
    uint64_t size;
} GateSet;


typedef struct bitset {
    uint8_t bits;
    Gate** wires;
} BitSet;
#define BS(n,w) ((BitSet){n, w})
#define NULL_BS ((BitSet){0, NULL})

Gate* init_gate(Gate* g) {
    g->flags = 0;
    g->code = 0;
    g->salt = 0;
    g->in_a = O(NULL);
    g->in_b = O(NULL);
    g->t_v = random() + 1;
    g->f_v = random() + 1;

    g->res = 0;
    g->out = O(NULL);
#if DEBUG 
    g->name = "<unkown>";
#endif
    return g;
}

typedef struct gateheap {
    Gate* memory;
    size_t alloc_size_bytes;
    size_t size;
} GateHeap;
GateHeap g_heap;

void init_gate_heap() {
    g_heap.alloc_size_bytes = 0x1000;
    g_heap.memory = mmap((void*)0x4040000, g_heap.alloc_size_bytes, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    assert(g_heap.memory != NULL);
    g_heap.size = 0;
}


Gate* gate_heap_alloc() {
    size_t byte_off = (g_heap.size+1) * sizeof(Gate);
    while (byte_off >= g_heap.alloc_size_bytes - 1) {
        size_t new_amt = 0x1000;
        void* new_page = (void*)((uintptr_t)(g_heap.memory) + g_heap.alloc_size_bytes);
        new_page = mmap(new_page, new_amt, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        assert(new_page != NULL);
        g_heap.alloc_size_bytes += new_amt;
    }
    return &g_heap.memory[g_heap.size++];
}

#ifdef PRODUCE_CODE
void link_graphvis_nodes(FILE* f, Gate* a, Gate* b) {
    fprintf(f, "  g_%p -> g_%p;\n", a, b);
}

void make_graphvis(char* file) {
     FILE* f = fopen(file,"w");
     assert(f != NULL);
     fprintf(f, "digraph G{\n");
     for (size_t i=0; i<g_heap.size; i++) {
         Gate* g = &g_heap.memory[i];
         if (g->type == g_MEMORY) {
             fprintf(f, "g_%p [shape=box,style=filled,color=\".7 .3 .7\"];\n",g);
         } else if (g->type == g_INPUT) {

             fprintf(f, "g_%p [shape=invhouse,style=filled,color=\".7 .3 1.0\"];\n",g);
         } else if (g->type == g_OUTPUT) {

             fprintf(f, "g_%p [shape=trapezium,style=filled,color=\"1.0 .3 7.0\"];\n",g);
         }
         Gate* o = P(g->out);
         if (o == NULL)
             continue;
         if (o->type == g_SET) {
             GateSet* s = (GateSet*)o;
             for (size_t j=0; j<s->size; j++) {
                 link_graphvis_nodes(f, g, s->children[j]);
             }
             continue;
         }
         link_graphvis_nodes(f, g, o);
     }
     fprintf(f, "}");
     fclose(f);
}
#endif


Gate* alloc_gate() {
    Gate* v =gate_heap_alloc();
#ifdef VERBOSE_ALLOC
    printf("alloc(%p)\n",v);
#endif
    init_gate(v);
    return v;
}
void* alloc_malloc_heap(size_t s) {
    void* v = malloc(s);
    assert((uint64_t)v < 0x100000000);
    return v;
}
// virtual gates are not saved
Gate* alloc_virtual_gate() {
    Gate* v = init_gate(alloc_malloc_heap(sizeof(Gate)));
#ifdef VERBOSE_ALLOC
    printf("valloc(%p)\n",v);
#endif
    return v;
}

Gate* devirtualize_gate(Gate* g) {
    if (g == NULL) return NULL;
    while (g->type == g_NOT || g->type == g_SET) {
        g = P(g->in_a);
        if (g == NULL)
            break;
    }
    return g;
}
#define IS_NOT(g) (g->type == g_NOT)
#define IS_NOTTED(g) (g?devirtualize_gate(g)->t_v != get_gate_val(g, 1) : 0)

GateSet* make_set(Gate* parent) {
    GateSet* set = (GateSet*)alloc_malloc_heap(sizeof(GateSet));
    set->type = g_SET;
    set->flags = 0;
    set->parent = parent;
    set->alloc_size = 16;
    set->children = calloc(set->alloc_size, sizeof(Gate));
    set->size = 0;
    return set;
}

Gate* push_set(GateSet* set, Gate* g) {
    if (set->size >= set->alloc_size-1) {
        set->alloc_size *= 2;
        set->children = reallocarray(
                set->children, set->alloc_size, sizeof(Gate));
    }
    set->children[set->size++] = g;
    return g;
}

BitSet push_set_bitset(GateSet* set, BitSet bs) {
    for (uint8_t i=0; i<bs.bits; i++)
        push_set(set, bs.wires[i]);
    return bs;
}

void add_out(Gate* in, Gate* out) {
    Gate* next = P(out->out);
    if (next == NULL) {
        out->out = O(in);
        return;
    }
    if (next->type != g_SET) {
        GateSet* set = make_set(out);
        push_set(set, next);
        push_set(set, in);
        out->out = O((Gate*)set);
    } else {
        push_set((GateSet*)next, in);
    }
}

void uses(Gate* in, Gate* out, GateHeapPtr* loc) {
    if (out == NULL || out->type == g_PLACEHOLDER) {
        *loc = O(NULL);
        return;
    }

    out = devirtualize_gate(out);

    *loc = O(out);

    add_out(in, out);
}

uint64_t get_gate_val(Gate* g, int bit) {
    while (g->type == g_NOT || g->type == g_SET) {
        if (g->type == g_NOT)
            bit = !bit;
        g = P(g->in_a);
    }
    if (bit)
        return g->t_v;
    return g->f_v;
}

Gate* INPUT() {
    Gate* i = alloc_gate();
    i->type = g_INPUT;
#ifdef VERBOSE_GATE_CREATION
    printf("Creating input(%p)\n", i);
#endif
    return i;
}
void set_input(Gate* i, int bit) {
    i->res = bit? i->t_v : i->f_v;
}
void set_value(Gate* i, int bit) {
    i->res = bit? i->t_v : i->f_v;
}

Gate* INPUT_with_val(int bit) {
    Gate* i = INPUT();
    set_input(i, bit);
    return i;
}

Gate* OUTPUT(Gate* a) {
    Gate* o = alloc_gate();
    o->type = g_OUTPUT;

    uses(o, a, &o->in_a);
    o->t_v = get_gate_val(a, 1);
    o->f_v = get_gate_val(a, 0);

#ifdef VERBOSE_GATE_CREATION
    printf("Creating output(%p) from %s[%p]\n", o, IS_NOTTED(a)?"!":"", P(o->in_a));
#endif

    return o;
}

Gate* MEMORY(Gate* a) {
    Gate* o = alloc_gate();
    o->type = g_MEMORY;
    if (a != NULL) {
        uses(o, a, &o->in_a);
        o->t_v = get_gate_val(a, 1);
        o->f_v = get_gate_val(a, 0);
    }

    set_value(o, 0);

#ifdef VERBOSE_GATE_CREATION
    printf("Creating memory(%p) from %s[%p]\n", o, IS_NOTTED(a)?"!":"", P(o->in_a));
#endif

    return o;
}

Gate* MEMORY_with_value(Gate* a, int bit) {
    Gate* m = MEMORY(a);
    set_value(m, bit);
    return m;
}



int get_value(Gate* o) {
    assert(o->res != 0);
    if (o->res == o->t_v) {
        return 1;
    }
    assert(o->res == o->f_v);
    return 0;
}
int get_output(Gate* o) {
    assert(o->res != 0);
    assert(P(o->in_a) != NULL);
    if (o->res == o->t_v) {
        return 1;
    }
    assert(o->res == o->f_v);
    return 0;
}




size_t g_num_nand_gates = 0;

void init_nand(Gate* nand, Gate* a, Gate* b) {
    if (a == NULL) a = P(nand->in_a);
    if (b == NULL) b = P(nand->in_b);

    assert(a != NULL);
    assert(b != NULL);

    uses(nand, a, &nand->in_a);
    uses(nand, b, &nand->in_b);

    uint64_t a_t_v = get_gate_val(a, 1);
    uint64_t a_f_v = get_gate_val(a, 0);
    uint64_t b_t_v = get_gate_val(b, 1);
    uint64_t b_f_v = get_gate_val(b, 0);

    uint16_t code;
    do {
        uint64_t salt = nand->salt;

        uint64_t s = pac_sign(a_t_v, b_t_v + salt);

        code = s >> 48;

        // Check that our nand gate holds for these values (no collision)
        if (pac_gate_res(code, a_t_v, b_t_v + salt) == 0 &&
            pac_gate_res(code, a_f_v, b_t_v + salt) == 1 &&
            pac_gate_res(code, a_t_v, b_f_v + salt) == 1 &&
            pac_gate_res(code, a_f_v, b_f_v + salt) == 1)
        {
            break;
        }

        assert(salt != 0xff);
        nand->salt++;
#ifdef VERBOSE_GATE_CREATION
        printf("Had pac collision, trying with salt: %u\n", nand->salt);
#endif
    } while(1);


#if VERBOSE_GATE_CREATION || DEBUG 
    {
        int a_t = a_t_v == P(nand->in_a)->t_v;
        assert(a_t || a_t_v == P(nand->in_a)->f_v);
        int b_t = b_t_v == P(nand->in_b)->t_v;
        assert(b_t || b_t_v == P(nand->in_b)->f_v);
        char name[100] = { 0 };
        sprintf(name, "<%xx%x=0>", a_t, b_t);

#ifdef VERBOSE_GATE_CREATION
        printf("Creating gate(%p) %s <%x> : (%s[%p], %s[%p])\n",
                nand, name, code, 
                a_t?"":"!",P(nand->in_a),
                b_t?"":"!",P(nand->in_b));
#endif
#if DEBUG
        nand->name = strdup(name);
#endif
    }
#endif

    nand->code = code;
    SET_FLAG(nand, f_UNINIT, 0);
}

Gate* PLACEHOLDER() {
    Gate* p = alloc_virtual_gate();
    p->type = g_PLACEHOLDER;
#ifdef VERBOSE_GATE_CREATION
    printf("Creating placeholder(%p)\n",p);
#endif
    return p;
}

Gate* NAND(Gate* a, Gate* b) {
    Gate* nand = alloc_gate();
    nand->type = g_NAND;
    Gate* a_d = devirtualize_gate(a);
    Gate* b_d = devirtualize_gate(b);
    if (a_d == NULL || b_d == NULL
#ifdef PRODUCE_CODE
        || a_d->type == g_PLACEHOLDER || b_d->type == g_PLACEHOLDER
#endif
    ) {
#ifdef PRODUCE_CODE
#ifdef SOL_DUMP
        nand->in_a = O(a_d);
        nand->in_b = O(b_d);
#else
        nand->in_a = O(a);
        nand->in_b = O(b);
#endif
#ifdef VERBOSE_GATE_CREATION
        printf("Creating uninit nand gate(%p) ([%p], [%p])\n",nand, a,b);
#endif
        if (a_d && a_d->type == g_PLACEHOLDER) {
            int is_virtual = (a == a_d);
            if (P(a_d->in_a) != NULL) {
                // Find tail of the list
                while(P(a_d->out) != NULL) { a_d = P(a_d->out); }
                Gate* np = PLACEHOLDER();
                a_d->out = O(np);
#ifdef VERBOSE_GATE_CREATION
                printf("Adding extra placeholder (%p)->next = %p\n", a_d, np);
#endif
                a_d = np;
            }
            a_d->in_a = O(nand);
            if (is_virtual) {
                a_d->code = 0;
                a_d->salt = 0;
                a_d->in_b = O(nand);
            } else {
                if (a->type != g_NOT) {
                    printf("GOT a %p vs ad %p\n",a,a_d);
                }
                assert(a->type == g_NOT);
                a_d->code = 0;
                a_d->salt = 0;
                a_d->in_b = O(a);
            }
#ifdef VERBOSE_PLACEHOLDERS
            printf("Installing placeholder[%p] for [%p]->[0] via nand %p->in_a | %u %u\n",
                    a_d,P(a_d->in_b),nand, a_d->code, a_d->salt);
#endif
        }
        if (b_d && b_d->type == g_PLACEHOLDER) {
            int is_virtual = (b == b_d);
            if (P(b_d->in_a) != NULL) {
                // Find tail of the list
                while(P(b_d->out) != NULL) { b_d = P(b_d->out); }
                Gate* np = PLACEHOLDER();
                b_d->out = O(np);
#ifdef VERBOSE_GATE_CREATION
                printf("Adding extra placeholder (%p)->next = %p\n", b_d, np);
#endif
                b_d = np;
            }
            b_d->in_a = O(nand);
            if (is_virtual) {
                b_d->code = 1;
                b_d->salt = 1;
                b_d->in_b = O(nand);
            } else {
                if (b->type != g_NOT) {
                    printf("GOT b %p vs bd %p\n",b, b_d);
                }
                assert(b->type == g_NOT);
                b_d->code = 0; // Not is always first slot
                b_d->salt = 1;
                b_d->in_b = O(b);
            }
#ifdef VERBOSE_PLACEHOLDERS
            printf("Installing placeholder[%p] for [%p]->[%u] via nand %p->in_b | %u %u\n",
                    b_d,P(b_d->in_b),b_d->code,nand, b_d->code, b_d->salt);
#endif
        }
#else
        nand->in_a = O(a_d);
        nand->in_b = O(b_d);
#endif
        SET_FLAG(nand, f_UNINIT, 1);
    } else {
        init_nand(nand, a, b);
    }

    g_num_nand_gates++;
    return nand;
}

#ifdef PRODUCE_CODE
void resolve_placeholder(Gate* p, Gate* c) {
    assert(p->type == g_PLACEHOLDER);
    assert(c->type != g_PLACEHOLDER);
    Gate* nand = P(p->in_a);
    assert(nand != NULL);

    Gate* holder = P(p->in_b);
    assert(holder!= NULL);
#ifdef VERBOSE_PLACEHOLDERS
    printf("Resolving placeholder[%p] for holder %p with %p via nand %p | %u %u\n",p,holder,c,nand, p->code, p->salt);
#endif
    p->in_a = O(NULL);

    if (p->code == 0) { // location to write
#ifdef VERBOSE_PLACEHOLDERS
        printf("Updating [%p]->in_a with %p\n",holder,c);
#endif
        holder->in_a = O(c);
    } else {
        assert(holder->type == g_NAND);
#ifdef VERBOSE_PLACEHOLDERS
        printf("Updating [%p]->in_b with %p\n",holder,c);
#endif
        holder->in_b = O(c);
    }
    Gate* o;
    // Check if other side is filled in
    if (p->salt == 0) // location in nand
        o = devirtualize_gate(P(nand->in_b));
    else
        o = devirtualize_gate(P(nand->in_a));
#ifdef VERBOSE_PLACEHOLDERS
        printf("checking nand[%p]->[%u] is %p\n",nand, 1-p->salt, o);
#endif
    if (o && o->type != g_PLACEHOLDER) {
#ifdef VERBOSE_PLACEHOLDERS
        printf("Initializing nand %p with [%p,%p]\n",nand, P(nand->in_a),P(nand->in_b));
#endif
        init_nand(nand, NULL, NULL);
    }
    Gate* next = P(p->out);
    if (next != NULL) {
        assert(next->type == g_PLACEHOLDER);
        resolve_placeholder(next, c);
    }
}
#endif


Gate* NOT(Gate* a) {
    Gate* not = alloc_virtual_gate();
    not->type = g_NOT;
    not->in_a = O(a);
#ifdef VERBOSE_GATE_CREATION
    printf("Creating NOT gate(%p) [%p]\n",not, a);
#endif
    return not;
}

Gate* AND(Gate* a, Gate* b) {
    return NOT(NAND(a,b));
}

Gate* OR(Gate* a, Gate* b) {
    return NAND(NOT(a), NOT(b));
}

Gate* XOR(Gate* a, Gate*b) {
    /*
    Gate* nand1 = NAND(NOT(a), b);
    Gate* nand2 = NAND(a, NOT(b));
    return OR(nand1, nand2);
    */
    
    /*
    Gate* nand1 = NAND(a, b);
    Gate* nand2 = NAND(a, nand1);
    Gate* nand3 = NAND(b, nand1);
    Gate* nand4 = NAND(nand2, nand3);
    return nand4;
    // */
#ifdef VERBOSE_GATE_CREATION
    printf(",-- XOR --\n");
#endif
    Gate* nand = NAND(a, b);
    Gate* or = OR(a, b);
    Gate* and = AND(nand, or);
#ifdef VERBOSE_GATE_CREATION
    printf("'-- %p --\n", and);
#endif
    return and;
    //*/
}

Gate* REGISTER(Gate* write, Gate* value) {
    Gate* nand = NAND(NULL, NULL);
    Gate* m = MEMORY(nand);

    Gate* not_write = NOT(write);
    Gate* m_v = NAND(not_write, m);
    Gate* w_v = NAND(write, value);

    init_nand(nand, m_v, w_v);
#ifdef VERBOSE_GATE_CREATION
    printf("Creating register(%p) with write %s[%p] and value %s[%p]\n",
            m,
            IS_NOTTED(write)?"!":"", P(w_v->in_a),
            IS_NOTTED(value)?"!":"", P(w_v->in_b));
#endif
    return m;
}


void run_gate(Gate* gate) {
    assert(gate->type == g_NAND);
#if DEBUG
    char* name = gate->name;
#else
    char* name = "";
#endif
#ifdef VERBOSE_GATE_EVAL
    printf("Evaling gate[%p]%s(%p, %p)\n", gate, name, P(gate->in_a), P(gate->in_b));
#endif
    uint64_t a = P(gate->in_a)->res;
    uint64_t b = P(gate->in_b)->res;
    assert(a != 0);
    assert(b != 0);

    if (gate->type != 0) {
        assert_m(0,"Unknown gate encountered");
    }
     
#ifdef VERBOSE_GATE_EVAL
    {
        int a_t = a == P(gate->in_a)->t_v;
        assert(a_t || a == P(gate->in_a)->f_v);
        int b_t = b == P(gate->in_b)->t_v;
        assert(b_t || b == P(gate->in_b)->f_v);
        printf(" '- %x x %x -> ", a_t, b_t);
    }
#endif

    a |= ((uint64_t)gate->code) << 48;
    a = pac_verify(a, b + gate->salt);

    uint16_t code = a >> 48;
#ifdef VERBOSE_GATE_EVAL
    printf("%u\n", code != 0);
#endif
    gate->res = code? gate->t_v : gate->f_v;
    assert(gate->res != 0);
}

typedef struct gatestack {
    uint32_t alloc_size;
    uint32_t size;
    Gate** stack;
} GateStack;

size_t g_queue_depth = 0;

GateStack* make_gate_stack(size_t size) {
    GateStack* g = alloc_malloc_heap(sizeof(GateStack));
    g->size = 0;
    g->alloc_size = size;
    g->stack = calloc(g->alloc_size, sizeof(Gate*));
    return g;
}

Gate* gate_stack_pop(GateStack* stack) {
    assert(stack->size > 0);

    Gate* v = stack->stack[--stack->size];
    stack->stack[stack->size] = NULL;
#ifdef VERBOSE_STACK
    printf("gate_stack_pop() = %p\n", v);
#endif
    return v;
}

void gate_stack_push(GateStack* stack, Gate* gate) {
    if (stack->size >= stack->alloc_size-1) {
        stack->alloc_size *= 2;
        stack->stack = reallocarray(
                stack->stack, stack->alloc_size, sizeof(Gate));
    }
#ifdef VERBOSE_STACK
    printf("gate_stack_push(%p)\n", gate);
#endif
    stack->stack[stack->size++] = gate;
    if (stack->size > g_queue_depth)
        g_queue_depth = stack->size;
}


// FIFO class
typedef struct gatering GateRing;
struct gatering {
    uint32_t alloc_size;
    uint32_t in;
    uint32_t out;
    uint32_t size;
    Gate** ring;
    GateRing* next;
};

GateRing* make_gate_ring(size_t size) {
    GateRing* g = alloc_malloc_heap(sizeof(GateRing));
    g->alloc_size = size;
    g->in = 0;
    g->out = 0;
    g->size = 0;
    g->next = NULL;
    g->ring = calloc(g->alloc_size, sizeof(Gate*));
    return g;
}

size_t gate_ring_push(GateRing* r, Gate* g) {
#ifdef VERBOSE_RING
    printf("Pushing gate %p to ring %p at %u\n", g, r, r->in);
#endif
    // If we have filled this ring, go to the next one
    if (r->next != NULL) {
        size_t n_size = gate_ring_push(r->next, g);
        n_size += r->size;
        if (n_size > g_queue_depth)
            g_queue_depth = n_size;
        return n_size;
    }
    // Check if we have space left
    if (r->size >= r->alloc_size) {
        assert(r->size == r->alloc_size);
        assert(r->next == NULL);
        // Create new ring
        r->next = make_gate_ring(r->alloc_size);
#ifdef VERBOSE_RING
        printf("Ran out of space in ring %p, creating ring %p\n", r, r->next);
#endif
        size_t n_size = gate_ring_push(r->next, g);
        n_size += r->size;
        if (n_size > g_queue_depth)
            g_queue_depth = n_size;
        return n_size;
    }

    r->ring[r->in] = g;
    r->size++;
    r->in++;
    if (r->in == r->alloc_size) {
        r->in = 0;
    }
    if (r->size > g_queue_depth)
        g_queue_depth = r->size;
    return r->size;
}

Gate* gate_ring_pop(GateRing* r) {
    assert(r->size > 0);
    Gate* g = r->ring[r->out];
#ifdef VERBOSE_RING
    printf("Popping gate %p from ring %p at %u\n", g, r, r->out);
#endif
    r->size--;
    r->out++;
    if (r->out == r->alloc_size) {
        r->out = 0;
    }
    // If we emptied this ring and have a second ring, copy it over
    if (r->size == 0 && r->next != NULL) {
        GateRing* next = r->next;
#ifdef VERBOSE_RING
        printf("Emptied ring %p, copying ring %p\n", r, next);
#endif
        free(r->ring);
        *r = *next;
        free(next);
    }
    return g;
}


#ifdef USE_RING
typedef GateRing GateQueue;
GateQueue* make_gate_queue(size_t size) {
    return make_gate_ring(size);
}
Gate* pop_gate(GateRing* r) {
    return gate_ring_pop(r);
}
void push_gate(GateRing* r, Gate* g) {
    gate_ring_push(r, g);
}
#else
typedef GateStack GateQueue;
GateQueue* make_gate_queue(size_t size) {
    return make_gate_stack(size);
}
Gate* pop_gate(GateStack* s) {
    return gate_stack_pop(s);
}
void push_gate(GateStack* s, Gate* g) {
    gate_stack_push(s, g);
}
#endif

#define ITER_CIRCUT_START(start, name) \
    GateQueue* to_visit = make_gate_queue(100); \
    push_gate(to_visit, start); \
    do { \
        Gate* name = pop_gate(to_visit); \
        if (name->type == g_SET) { \
            GateSet* set = (GateSet*)name; \
            for (size_t i=0; i<set->size; i++) { \
                push_gate(to_visit, set->children[i]); \
            } \
            continue; \
        }

#define ITER_CIRCUT_END(name) \
        if (P(name->out) == NULL) continue; \
        push_gate(to_visit, P(name->out)); \
    } while (to_visit->size != 0);

void propigate_memory(Gate* m, int val) {
    if (m == NULL) return;
    if (m->type != g_MEMORY) return;
#ifdef VERBOSE_MEMORY
    printf("Updating memory[%p] to %u\n", m, val);
#endif
    set_value(m, val);
}

void _reset_circuit(Gate* start, int clear_memory) {
    ITER_CIRCUT_START(start, gate) {
        if (gate->res == 0)
            continue;

        if (gate->type == g_MEMORY) {
            if (clear_memory) {
                set_value(gate, 0);
            }
        } else {
            Gate* next = P(gate->out);
            if (next && !clear_memory) {
                int v = get_value(gate);
                if (next->type == g_SET) {
                    GateSet* set = (GateSet*)next;
                    for (size_t i=0; i<set->size; i++) {
                        propigate_memory(set->children[i], v);
                        push_gate(to_visit, set->children[i]);
                    }
                } else {
                    propigate_memory(next, v);
                }
            }
            if (gate->type != g_INPUT) {
#ifdef VERBOSE_RESET
                printf("Resetting %p\n", gate);
#endif
                gate->res = 0;
            }
        }
    } ITER_CIRCUT_END(gate);
#ifdef VERBOSE_RESET
    puts("Done reset");
#endif
}

void reset_circuit(Gate* start) {
    _reset_circuit(start, 1);
}

void process_output(GateQueue* to_run, Gate* next) {
#ifdef VERBOSE_PROCESS
    printf("process_output %p %hx\n",next, next->type);
#endif
    assert(next != NULL);
    if (next->type == g_SET) {
        GateSet* set = (GateSet*)next;
        for (size_t i=0; i<set->size; i++) {
            process_output(to_run, set->children[i]);
        }
        return;
    }
    if (next->type == g_MEMORY) {
        // We don't update memory until end of cycle
        // But we can keep propigating the circuit with the old value
        Gate* o = P(next->out);
        if (o == NULL)
            return;
        process_output(to_run, o);
        return;
    }
    if (next->type == g_OUTPUT) {
        next->res = P(next->in_a)->res;
        assert(next->res != 0);
#ifdef VERBOSE_IO
        int v = next->res == next->t_v;
        assert(v || next->res == next->f_v);
        int is_n = next->f_v == P(next->in_a)->t_v;
        printf("Output[%p] = %u from %s[%p]\n", next, v, is_n?"!":"", P(next->in_a));
#endif
        if (HAS_FLAG(next, f_SANITY) && !get_value(next)) {
            if (HAS_FLAG(next, f_SANITY_DECODE)) {
#ifdef SWAP_INST_BITS
                puts("\033[31mFailed architecture sanity check!! You are using instructions built for the wrong program, they will not decode correctly!\033[0m");
#else
                puts("\033[31mFailed architecture sanity check!! Unable to decode instructions correctly, expected START but got something else...\033[0m");
#endif
            } else {
                puts("\033[31mFailed logic sanity check!! Make sure you are using the correct license file for this program...\033[0m");
            }
            assert(0);
        }
        return;
    }
    if (next->type == g_INPUT) {
        Gate* o = P(next->out);
        if (o == NULL)
            return;
        process_output(to_run, o);
        return;
    }
    assert(next->type == g_NAND);
    if (next->res != 0)
        return;
    if (P(next->in_a)->res == 0 || P(next->in_b)->res == 0)
        return;
    push_gate(to_run, next);
}

void run_circuit(Gate* start) {
    GateQueue* to_run = make_gate_queue(100);
    push_gate(to_run, start);
    do {
        Gate* gate = pop_gate(to_run);
#ifdef PRODUCE_CODE
        if (HAS_FLAG(gate, f_UNINIT)) {
            printf("%p UNINIT\n",gate);
        }
        assert(!HAS_FLAG(gate, f_UNINIT));
#endif

        if (gate->type == g_SET || gate->type == g_INPUT || gate->type == g_MEMORY) {
            process_output(to_run, gate);
            continue;
        }

        if (gate->res != 0) {
#ifdef VERBOSE_PROCESS
            printf("Skipping gate %p (already evaled)\n", gate);
#endif
            continue;
        }

        //TODO we can skip gates that have no output?
        run_gate(gate);

        Gate* next = P(gate->out);
        if (next == NULL)
            continue;

        process_output(to_run, next);

    } while (to_run->size != 0);
#ifdef VERBOSE_CLOCK_CYCLE
    puts("Clock cycle is done");
#endif
}


#define GATE_TEST(a, b, e) \
    reset_circuit((Gate*)ts); \
    set_input(i0, a); \
    set_input(i1, b); \
    run_circuit((Gate*)ts); \
    assert(get_output(o) == e);

void test_nand() {
    thputs("=== TEST NAND ===");
    GateSet* ts = make_set(NULL);
    Gate* i0 = push_set(ts, INPUT());
    Gate* i1 = push_set(ts, INPUT());
    Gate* nand = NAND(i0, i1);
    Gate* o = OUTPUT(nand);

    thputs("~(1&1)");
    GATE_TEST(1, 1, 0);

    thputs("~(0&1)");
    GATE_TEST(0, 1, 1);

    thputs("~(1&0)");
    GATE_TEST(1, 0, 1);

    thputs("~(0&0)");
    GATE_TEST(0, 0, 1);

    puts("=== TEST OK ===");
}

void test_and() {
    thputs("=== TEST AND ===");
    GateSet* ts = make_set(NULL);
    Gate* i0 = push_set(ts, INPUT());
    Gate* i1 = push_set(ts, INPUT());
    Gate* nand = AND(i0, i1);
    Gate* o = OUTPUT(nand);

    thputs("(1&1)");
    GATE_TEST(1, 1, 1);

    thputs("(0&1)");
    GATE_TEST(0, 1, 0);

    thputs("(1&0)");
    GATE_TEST(1, 0, 0);

    thputs("(0&0)");
    GATE_TEST(0, 0, 0);

    puts("=== TEST OK ===");
}

void test_or() {
    thputs("=== TEST OR ===");
    GateSet* ts = make_set(NULL);
    Gate* i0 = push_set(ts, INPUT());
    Gate* i1 = push_set(ts, INPUT());
    Gate* nand = OR(i0, i1);
    Gate* o = OUTPUT(nand);

    thputs("(1|1)");
    GATE_TEST(1, 1, 1);

    thputs("(0|1)");
    GATE_TEST(0, 1, 1);

    thputs("(1|0)");
    GATE_TEST(1, 0, 1);

    thputs("(0|0)");
    GATE_TEST(0, 0, 0);

    puts("=== TEST OK ===");
}

void test_xor() {
    thputs("=== TEST XOR ===");
    GateSet* ts = make_set(NULL);
    Gate* i0 = push_set(ts, INPUT());
    Gate* i1 = push_set(ts, INPUT());
    Gate* nand = XOR(i0, i1);
    Gate* o = OUTPUT(nand);

    thputs("(1^1)");
    GATE_TEST(1, 1, 0);

    thputs("(0^1)");
    GATE_TEST(0, 1, 1);

    thputs("(1^0)");
    GATE_TEST(1, 0, 1);

    thputs("(0^0)");
    GATE_TEST(0, 0, 0);

    puts("=== TEST OK ===");
}

#undef GATE_TEST

//#ifdef DEBUG
#if 1
void test_register() {
    //puts("=== TEST REGISTER ===");
    GateSet* ts = make_set(NULL);
    Gate* w = push_set(ts, INPUT());
    Gate* v = push_set(ts, INPUT());
    Gate* reg = push_set(ts, REGISTER(w, v));
    Gate* o = OUTPUT(reg);

    // Full reset
    reset_circuit((Gate*)ts);

#define TEST_REG(wv,vv,c,n) \
    set_input(w, wv); \
    set_input(v, vv); \
    run_circuit((Gate*)ts); \
    assert(get_value(reg) == c); \
    assert(get_output(o) == c); \
    _reset_circuit((Gate*)ts, 0); \
    assert(get_value(reg) == n); \

    TEST_REG(0,1, 0,0);

    TEST_REG(1,1, 0,1);

    TEST_REG(0,0, 1,1);

    TEST_REG(1,0, 1,0);

    TEST_REG(0,1, 0,0);

#undef TEST_REG

    puts("=== REGISTER OK ===");
}
#endif


Gate* make_half_adder(Gate* a, Gate* b, Gate** c_out) {
    if (c_out != NULL) {
        *c_out = AND(a, b);
    }
    return XOR(a, b);
}

#ifdef PRODUCE_CODE
void test_half_adder() {
    puts("=== TEST HALF ADDER ===");
    GateSet* ts = make_set(NULL);
    Gate* i0 = push_set(ts, INPUT());
    Gate* i1 = push_set(ts, INPUT());

    Gate* carry;
    Gate* adder = make_half_adder(i0, i1, &carry);
    Gate* o0 = OUTPUT(adder);
    Gate* o1 = OUTPUT(carry);

#define TEST(a, b, s, c) \
    reset_circuit((Gate*)ts); \
    set_input(i0, a); \
    set_input(i1, b); \
    run_circuit((Gate*)ts); \
    assert(get_output(o0) == s); \
    assert(get_output(o1) == c);

    puts("0 + 0");
    TEST(0, 0, 0, 0);
    puts("0 + 1");
    TEST(0, 1, 1, 0);
    puts("1 + 0");
    TEST(1, 0, 1, 0);
    puts("1 + 1");
    TEST(1, 1, 0, 1);

#undef TEST
    puts("=== HALF ADDER OK ===");
}
#endif

Gate* make_full_adder(Gate* a, Gate* b, Gate* c_in, Gate** c_out) {
    Gate* xor = XOR(a, b);
    if (c_out != NULL) {
        Gate* and1 = AND(a, b);
        Gate* and2 = AND(xor, c_in);
        *c_out = OR(and1, and2);
    }
    return XOR(xor, c_in);
}

BitSet make_full_adder_bitset(BitSet a, BitSet b, Gate* carry, Gate** c_out) {
    assert(a.bits == b.bits);
    uint8_t width = a.bits;
    Gate** out = calloc(width, sizeof(Gate*));
    for (uint8_t i=0; i<width; i++) {
        Gate* next_carry = NULL;
        out[i] = make_full_adder(a.wires[i], b.wires[i], carry, &next_carry);
        carry = next_carry;
    }
    *c_out = carry;
    return BS(width, out);
}

#ifdef PRODUCE_CODE
void test_full_adder() {
    puts("=== TEST FULL ADDER ===");
    GateSet* ts = make_set(NULL);
    Gate* i0 = push_set(ts, INPUT());
    Gate* i1 = push_set(ts, INPUT());
    Gate* i2 = push_set(ts, INPUT());

    Gate* carry;
    Gate* adder = make_full_adder(i0, i1, i2, &carry);
    Gate* o0 = OUTPUT(adder);
    Gate* o1 = OUTPUT(carry);

    for (int i=0; i<8; i++) {
        int a = i & 1;
        int b = (i >> 1) & 1;
        int c = (i >> 2) & 1;
        printf("%u+%u+[%u]\n", a,b,c);
        int r = a+b+c;
        reset_circuit((Gate*)ts);
        set_input(i0, a);
        set_input(i1, b);
        set_input(i2, c);
        run_circuit((Gate*)ts);
        assert(get_output(o0) == (r&1));
        assert(get_output(o1) == (r>>1));
    }

    puts("=== FULL ADDER OK ===");
}
#endif

BitSet make_input_bitset(uint8_t bits) {
    Gate** in = calloc(bits, sizeof(Gate*));
    for (uint8_t b=0; b<bits; b++) {
        in[b] = INPUT();
    }
    return BS(bits, in);
}
BitSet make_output_bitset(BitSet in) {
    Gate** out = calloc(in.bits, sizeof(Gate*));
    for (uint8_t b=0; b<in.bits; b++) {
        out[b] = OUTPUT(in.wires[b]);
    }
    return BS(in.bits, out);
}
void set_input_bitset(BitSet in, uint64_t val) {
    for (uint8_t b=0; b<in.bits; b++) {
        set_input(in.wires[b], (val>>b)&1);
    }
}

BitSet set_value_bitset(BitSet in, uint64_t val) {
    for (uint8_t b=0; b<in.bits; b++) {
        set_value(in.wires[b], (val>>b)&1);
    }
    return in;
}

uint64_t get_value_bitset(BitSet o) {
    uint64_t r = 0;
    for (uint8_t b=0; b<o.bits; b++) {
        uint64_t bit = get_value(o.wires[b]);
        r |= bit << b;
    }
    return r;
}

BitSet make_placeholder_bitset(uint8_t bits) {
    Gate** in = calloc(bits, sizeof(Gate*));
    for (uint8_t b=0; b<bits; b++) {
        in[b] = PLACEHOLDER();
    }
    return BS(bits, in);
}
BitSet make_memory_bitset(BitSet in) {
    Gate** out = calloc(in.bits, sizeof(Gate*));
    for (uint8_t b=0; b<in.bits; b++) {
        out[b] = MEMORY(in.wires[b]);
    }
    return BS(in.bits, out);
}

#ifdef PRODUCE_CODE
void resolve_placeholder_bitset(BitSet p, BitSet in) {
    assert(p.bits == in.bits);
    for (uint8_t b=0; b<p.bits; b++) {
        resolve_placeholder(p.wires[b], in.wires[b]);
    }
}
#endif

Gate* make_bit_andor(BitSet input_bs, int is_and) {
    Gate** input = input_bs.wires;
    uint8_t num_bits = input_bs.bits;
    if (num_bits == 1) return input[0];
    if (num_bits == 2) {
        if (is_and)
            return AND(input[0], input[1]);
        return OR(input[0], input[1]);
    }

    uint8_t p = num_bits / 2;
    Gate* a = make_bit_andor(BS(p,input), is_and);
    Gate* b = make_bit_andor(BS(num_bits-p,input + p), is_and);
    if (is_and)
        return AND(a,b);
    return OR(a,b);
}

// Return malloc array of output selected by a given input bit pattern
BitSet make_decoder(BitSet input_bs) {
#ifdef VERBOSE_GATE_CREATION
    puts(",-- DECODER --,");
#endif
    uint8_t num_bits = input_bs.bits;
    Gate** input = input_bs.wires;
    Gate** nots = calloc(num_bits, sizeof(Gate*));
    for (uint8_t b=0; b < num_bits; b++) {
        nots[b] = NOT(input[b]);
    }

    size_t num = 1 << num_bits;
    Gate** output = calloc(num, sizeof(Gate*));

    Gate** select = calloc(num_bits, sizeof(Gate*));
    for (uint64_t i = 0; i<num; i++) {
        for (uint8_t b=0; b < num_bits; b++) {
            uint8_t bit = (i>>b)&1;
            select[b] = bit? input[b] : nots[b];
#ifdef VERBOSE_GATE_CREATION
            printf("%lu -> select[%u] %u? %p\n",i,b,bit,select[b]);
#endif
        }
        output[i] = make_bit_andor(BS(num_bits, select), 1);
    }
    free(nots);
    free(select);
#ifdef VERBOSE_GATE_CREATION
    puts("'-- DECODER --'");
#endif
    return BS(num, output);
}

BitSet make_demux(BitSet selector, Gate* value) {
    BitSet decoded = make_decoder(selector);
    Gate** wires = decoded.wires;
    for (uint64_t i=0; i<decoded.bits; i++) {
        Gate* a = AND(wires[i], value);
        wires[i] = a;
    }
    return decoded;
}

#ifdef PRODUCE_CODE
void test_decoder() {
    puts("=== TEST DECODER ===");
    GateSet* ts = make_set(NULL);

    uint8_t num_in = 4;
    Gate** in = calloc(num_in, sizeof(Gate*));
    for (uint8_t i=0; i<num_in; i++) {
        in[i] = push_set(ts, INPUT());
    }
    uint64_t num_out = 1<<num_in;

    BitSet decoded_bs = make_decoder(BS(num_in, in));
    Gate** decoded = decoded_bs.wires;

    Gate** out = calloc(1 << num_in, sizeof(Gate*));
    for (uint8_t i=0; i<num_out; i++) {
        out[i] = OUTPUT(decoded[i]);
    }

    for (uint8_t v = 0; v < num_out; v++) {
        for (int i=0; i<num_in; i++) {
            set_input(in[i], (v>>i)&1);
        }

        reset_circuit((Gate*)ts);
        run_circuit((Gate*)ts);

        for (uint8_t i=0; i<num_out; i++) {
            uint64_t bit = get_output(out[i]);
            printf("%u: %lu\n", i, bit);
            if (bit) {
                assert(i == v);
            } else {
                assert(i != v);
            }
        }
    }


    puts("=== DECODER OK ===");
}
#endif

typedef struct regbank {
    uint8_t num;
    uint8_t width;
    BitSet* regs;
} RegBank;

#define RegBank(n, w, r) ((RegBank){ n, w, r})

RegBank make_readonly_memory(uint8_t num_reg, uint8_t width) {
    BitSet* regs = calloc(num_reg, sizeof(BitSet));
    for (uint8_t i=0; i<num_reg; i++) {
#ifdef VERBOSE_GATE_CREATION
        printf(",-- RO REGISTER[%u] --,\n", width);
#endif
        Gate** mem = calloc(width, sizeof(Gate*));

        // Allocate each bit of memory for the register
        for (uint8_t b=0; b<width; b++) {
            mem[b] = MEMORY_with_value(NULL, 0);
        }
#ifdef VERBOSE_GATE_CREATION
        printf("'-- RO REGISTER[%u] --'\n", width);
#endif
        regs[i] = BS(width, mem);
    }
    return RegBank(num_reg, width, regs);
}

RegBank make_register_bank(
        uint8_t num_reg, uint8_t width,
        BitSet selector,
        Gate* write_flag, BitSet write_val
) {
    BitSet* regs = calloc(num_reg, sizeof(BitSet));

    uint64_t max_reg = 1<<selector.bits;
    assert_h(num_reg <= max_reg, "Too many registers for to decode");

    assert(write_flag != NULL);

    // Generate a decoder and connect to the write part of the registers
    assert(write_val.bits == width);

    Gate** decoded;
    if (num_reg == 1) {
        // No decoder needed
        Gate** mem = calloc(width, sizeof(Gate*));
        decoded = calloc(1, sizeof(Gate*));
        decoded[0] = write_flag;
    } else {
        BitSet decoded_bs = make_demux(selector, write_flag);
        assert(decoded_bs.bits == max_reg);
        decoded = decoded_bs.wires;
    }

    for (uint8_t i=0; i<num_reg; i++) {
#ifdef VERBOSE_GATE_CREATION
        printf(",-- REGISTER[%u] --,\n", width);
#endif
        Gate* flag = decoded[i];
        Gate** mem = calloc(width, sizeof(Gate*));

        // Allocate each bit of memory for the register
        for (uint8_t b=0; b<width; b++) {
            mem[b] = REGISTER(flag, write_val.wires[b]);
        }
        regs[i] = BS(width, mem);
#ifdef VERBOSE_GATE_CREATION
        printf("'-- REGISTER[%u] --'\n", width);
#endif
    }
    free(decoded);
    return RegBank(num_reg, width, regs);
}

BitSet mux_two(BitSet a, BitSet b, Gate* ctl) {
    Gate* nctl = NOT(ctl);
    uint8_t width = a.bits;
    assert(width == b.bits);
    Gate** out = calloc(width, sizeof(Gate*));
    for (int8_t i=0; i<width; i++) {
        Gate* na = NAND(nctl, a.wires[i]);
        Gate* nb = NAND(ctl, b.wires[i]);
        out[i] = NAND(na, nb);
    }
    return BS(width, out);
}


BitSet mux_register_bank(RegBank bank, BitSet selector) {
    uint8_t width = bank.width;

    BitSet decoded_bs = make_decoder(selector);
    assert_h(decoded_bs.bits >= bank.num, "Too many registers too decode");

    Gate** decoded = decoded_bs.wires;

    Gate*** ors = calloc(width, sizeof(Gate**));
    for (uint64_t b=0; b<width; b++) {
        ors[b] = calloc(bank.num, sizeof(Gate*));
    }

#ifdef VERBOSE_GATE_CREATION
    printf(",-- MUX-AND --,\n");
#endif
    for (uint64_t r=0; r<bank.num; r++) {
        BitSet reg = bank.regs[r];
        for (uint64_t b=0; b<reg.bits; b++) {
            Gate* a = AND(decoded[r], reg.wires[b]);
            ors[b][r] = a;
        }
    }
#ifdef VERBOSE_GATE_CREATION
    printf("'-- MUX-AND --'\n");
    printf(",-- MUX-OR --,\n");
#endif
    Gate** out = calloc(width, sizeof(Gate*));
    for (uint64_t b=0; b<width; b++) {
        // Or all bits together
        out[b] = make_bit_andor(BS(bank.num, ors[b]), 0);
        free(ors[b]);
    }
#ifdef VERBOSE_GATE_CREATION
    printf("'-- MUX-OR --'\n");
#endif
    free(ors);
    free(decoded);
    return BS(width, out);
}

#ifdef PRODUCE_CODE
void test_register_bank() {
    puts("=== TEST REGBANK ===");
    GateSet* ts = make_set(NULL);

    const uint8_t sel_bits = 2;
    const uint8_t width = 16;
    const uint8_t num_reg = 1<<sel_bits;

    Gate* write_flag = push_set(ts, INPUT());
    BitSet write_val = make_input_bitset(width);
    push_set_bitset(ts, write_val);
    BitSet w_selector = make_input_bitset(sel_bits);
    push_set_bitset(ts, w_selector);
    BitSet r_selector = make_input_bitset(sel_bits);
    push_set_bitset(ts, r_selector);

    RegBank regs = make_register_bank(num_reg, width, w_selector, write_flag, write_val);

    BitSet sel_reg = mux_register_bank(regs, r_selector);
    BitSet read_val = make_output_bitset(sel_reg);

    reset_circuit((Gate*)ts);

    uint64_t exp[num_reg] = { 0 };
    for (uint8_t rn=0; rn<num_reg+1; rn++) {
        uint64_t vn = random();
        set_input_bitset(w_selector, rn);
        set_input_bitset(write_val, vn);
        if (rn < num_reg) {
            exp[rn] = get_value_bitset(write_val);
            set_input(write_flag, 1);
        } else {
            set_input(write_flag, 0);
        }

        run_circuit((Gate*)ts);
        _reset_circuit((Gate*)ts, 0);

        for (uint8_t i=0; i<num_reg; i++) {
            uint64_t v = get_value_bitset(regs.regs[i]);
            printf("%u: %lx\n", i,v);
            assert(exp[i] == v);
        }
    }

    for (uint8_t rn=0; rn<num_reg; rn++) {
        set_input(write_flag, 0);
        set_input_bitset(r_selector, rn);
        run_circuit((Gate*)ts);

        uint64_t v = get_value_bitset(read_val);
        printf("%u: %lx\n", rn,v);
        assert(exp[rn] == v);

        _reset_circuit((Gate*)ts, 0);
    }

    puts("=== REGBANK OK ===");
}
#endif

enum aluop {
    alu_SHIFT,
    alu_XOR,
    alu_ADD,
    alu_AND,
};

typedef struct alu {
    BitSet out;
    Gate* carry;
    Gate* overflow;
    Gate* zero;
} ALU;

ALU make_alu(BitSet op, BitSet in_a_bs, BitSet in_b_bs) {
    uint8_t width = in_a_bs.bits;
    assert(width == in_b_bs.bits);
    assert_h(op.bits >= 2, "Not enough bits for op");
    //c0 c1
    // 1  0 = XOR
    // 0  0 = ROT5
    // 0  1 = ADD
    // 1  1 = SUB
    Gate* c0 = op.wires[0]; // Which op
    Gate* c1 = op.wires[1]; // Add or Sub

    Gate** in_a = in_a_bs.wires;
    Gate** in_b = in_b_bs.wires;


    // 0 Bitwise Shift by 5
    Gate** shift_out = calloc(width, sizeof(Gate*));
    for (uint8_t i=0; i<width; i++) {
        shift_out[(i+5)%width] = in_a[i];
    }

    // 1 Bitwise Xor
    Gate** xor_out = calloc(width, sizeof(Gate*));
    for (uint8_t b=0; b<width; b++) {
        xor_out[b] = XOR(in_a[b], in_b[b]);
    }


    BitSet shift_or_out = mux_two(BS(width, shift_out), BS(width, xor_out), c0);

    // Add / Sub
    Gate* carry = NULL;
    Gate* carry_in = MEMORY_with_value(NULL, 0);

    /*
     Gate* carry_in = c0;
     * needed for subtraction
    BitSet b_xor = BS(width, calloc(width, sizeof(Gate*)));
    for (uint8_t b=0; b<width; b++) {
        b_xor.wires[b] = XOR(c0, in_b[b]);
    }
    */

    Gate** and_out = calloc(width, sizeof(Gate*));
    for (uint8_t b=0; b<width; b++) {
        and_out[b] = AND(in_a[b], in_b[b]);
    }

    BitSet adder_out = make_full_adder_bitset(in_a_bs, in_b_bs, carry_in, &carry);
    Gate* a_s = in_a[width-1];
    Gate* b_s = in_b[width-1];
    Gate* o_s = adder_out.wires[width-1];

    BitSet adder_and_out = mux_two(adder_out, BS(width, and_out), c0);





    /*
    for (uint8_t b=0; b<width; b++) {
        Gate* next_carry;
        a_s = in_a[b];
        b_s = in_b[b];
        Gate* x = XOR(c0, b_s);
        o_s = make_full_adder(a_s, x, carry, &next_carry);
        adder_out[b] = o_s;
        carry = next_carry;
    }
    */

    Gate* overflow = OR(
        AND(AND(NOT(a_s),NOT(b_s)), o_s),
        AND(AND(a_s, b_s), NOT(o_s))
    );

    ALU out;
    out.out = mux_two(shift_or_out, adder_and_out, c1);
    out.carry = carry;
    out.zero = NOT(make_bit_andor(out.out, 0));
    out.overflow = overflow;
    return out;
}

#ifdef PRODUCE_CODE
#endif


#ifdef DEBUG
void test_add(uint64_t a, uint64_t b) {
    GateSet* is = make_set(NULL);
    int bits = 64;
    Gate* a_in[bits];
    Gate* b_in[bits];
    Gate* out[bits];
    Gate* c_in = INPUT_with_val(0);
    for (int i=0; i<bits; i++) {
        a_in[i] = push_set(is, INPUT_with_val((a>>i)&1));
        b_in[i] = push_set(is, INPUT_with_val((b>>i)&1));
        Gate* next_carry;
        Gate* sum = make_full_adder(a_in[i], b_in[i], c_in, &next_carry);
        c_in = next_carry;
        out[i] = OUTPUT(sum);
    }

    reset_circuit((Gate*)is);
    run_circuit((Gate*)is);

    uint64_t res = 0;
    for (uint8_t i=0; i<bits; i++) {
        uint64_t bit = get_output(out[i]);
        res |= (bit << i);
    }
    printf("result = 0x%lx\n",res);
    assert(res == a + b);
}

void test_placeholders() {
    puts("=== TEST PLACEHOLDERS ===");

    GateSet* ts = make_set(NULL);

    Gate* p1 = PLACEHOLDER();
    Gate* p2 = PLACEHOLDER();

    Gate* a = XOR(p1, p2);

    Gate* m = push_set(ts, MEMORY(a));
    Gate* m2 = push_set(ts, MEMORY_with_value(NOT(a), 1));

    resolve_placeholder(p1, m);
    resolve_placeholder(p2, m2);

    Gate* out = OUTPUT(a);

    reset_circuit((Gate*)ts);
    run_circuit((Gate*)ts);

    int b = get_value(out);
    printf("out %u\n", b);

}
#endif

#define MEM_ADDR_BITS 5

typedef struct circuitinfo {
    uint32_t max_cycles;
    uint32_t max_run_time;
    GateHeapPtr do_out;
    GateHeapPtr out_char[8];
    GateHeapPtr do_in;
    GateHeapPtr in_char[8];
    GateHeapPtr halt;
    GateHeapPtr halt_bad_memory;
    GateHeapPtr give_flag;
    GateHeapPtr mem_addr[MEM_ADDR_BITS];
    GateHeapPtr mem_char[8];
    uint8_t memory[1<<MEM_ADDR_BITS];
#ifdef DEBUG_CPU
    BitSet pc;
    RegBank regs;
#endif
} CircutInfo;

void build_heap_backrefs(GateSet* sources) {
     for (size_t i=0; i<g_heap.size; i++) {
         Gate* g = &g_heap.memory[i];
         if (g->in_a != 0) {
             add_out(g, P(g->in_a));
         }
         if (g->in_b != 0) {
             add_out(g, P(g->in_b));
         }
         if (g->type == g_MEMORY || g->type == g_INPUT) {
             push_set(sources, g);
         }
     }
}

void give_flag() {
    FILE* f = fopen("/data/flag.txt","r");
    assert_m(f != NULL, "Could not find flag file");

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* data = calloc(len,1);
    fread(data, len, 1, f);
    fclose(f);
    printf("Flag pin activated! Here is your flag: %s\n", data);
    exit(0);
}


void run_circuit_with_info(CircutInfo* info, GateSet* sources) {
    assert(info->halt);
    Gate* halt = P(info->halt);
    Gate* halt_bad_memory = P(info->halt_bad_memory);
    Gate* flag = P(info->give_flag);

    uint8_t* input = NULL;

    //input = "?0123456789012345678?";

    Gate* do_out = P(info->do_out);
    BitSet out_char = BS(8, calloc(8, sizeof(Gate*)));
    if (do_out != NULL) {
        for (uint32_t i=0; i<8; i++) {
            Gate* g = P(info->out_char[i]);
            if (g == NULL) {
                do_out = NULL;
                break;
            }
            out_char.wires[i] = g;
        }
    }

    Gate* do_in = P(info->do_in);
    BitSet in_char = BS(8, calloc(8, sizeof(Gate*)));
    if (do_in != NULL) {
        for (uint32_t i=0; i<8; i++) {
            Gate* g = P(info->in_char[i]);
            if (g == NULL) {
                do_in = NULL;
                break;
            }
            in_char.wires[i] = g;
        }
    }

    int access_memory = 1;
    BitSet mem_addr = BS(MEM_ADDR_BITS, calloc(MEM_ADDR_BITS, sizeof(Gate*)));
    for (uint32_t i=0; i<MEM_ADDR_BITS; i++) {
            Gate* g = P(info->mem_addr[i]);
            if (g == NULL) {
                access_memory = 0;
                break;
            }
            mem_addr.wires[i] = g;
    }
    BitSet mem_char = BS(8, calloc(8, sizeof(Gate*)));
    for (uint32_t i=0; access_memory && i<8; i++) {
            Gate* g = P(info->mem_char[i]);
            if (g == NULL) {
                access_memory = 0;
                break;
            }
            mem_char.wires[i] = g;
    }


    for (uint32_t i=0; i<info->max_cycles; i++) {
        run_circuit((Gate*)sources);

        if (do_out && get_value(do_out)) {
            uint8_t cout = get_value_bitset(out_char);
            fwrite(&cout, 1, 1, stdout);
        }
        int actually_do_in = 0;
        if (do_in && get_value(do_in)) {
            actually_do_in = 1;
        }
        if (access_memory) {
            uint8_t addr = get_value_bitset(mem_addr);
            uint8_t c = info->memory[addr];
#ifdef PRODUCE_CODE
            printf("Fetching memory[%x]=%hx\n",addr,c);
#endif
            set_value_bitset(mem_char, c);
        }

        if (flag && get_value(flag)) {
            give_flag();
        }

        uint8_t do_halt = get_value(halt);
        if (do_halt) {
            if (halt_bad_memory) {
                uint8_t is_bad_memory = get_value(halt_bad_memory);
                if (is_bad_memory) {
                    puts("\033[31mFailed memory sanity check!! You probably forgot to set the correct inital values for the memory cells...\033[0m");
                }
            }
#ifdef PRODUCE_CODE
            printf("Halting after %u cycles!\n", i);
#else
            //printf("Halting after %u cycles!\n", i);
#endif
            break;
        }

#ifdef DEBUG_CPU
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')
        uint8_t pc = get_value_bitset(info->pc);
        uint8_t ins = info->memory[pc];
        printf("PC=%u ("BYTE_TO_BINARY_PATTERN")\n",pc,BYTE_TO_BINARY(ins));
#endif

        _reset_circuit((Gate*)sources, 0);

        if (actually_do_in) {
            if (input == NULL) {
                input = calloc(1,128);
                puts("Please enter input to send to program:");
                fgets((char*)input, 128-1, stdin);
                char* newl = strchr((char*)input, '\n');
                if (newl) *newl = 0;
                puts("Input recorded, continuing program...");
                g_start_t = time(NULL);
            }

            //uint8_t c = 'A'; //TODO
            uint8_t c = *input;
            if (c != 0) input++;
#ifdef PRODUCE_CODE
            printf("Reading input %hx\n",c);
#endif
            set_value_bitset(in_char, c);
        }
#ifdef DEBUG_CPU
        for (uint8_t i=0; i<info->regs.num; i++) {
            printf("R%u=%02x\n",i, get_value_bitset(info->regs.regs[i]));
        }
#endif
    }
}

void save_gate_heap(char* file, CircutInfo* info) {
    uint32_t heap_start = O(g_heap.memory);
    uint32_t heap_end = heap_start + g_heap.alloc_size_bytes;
    puts("Preparing heap to be saved to file");
     for (size_t i=0; i<g_heap.size; i++) {
         Gate* g = &g_heap.memory[i];
         if (g->type == g_MEMORY || g->type == g_INPUT) {
             //g->res = g->f_v;
         } else {
             g->res = 0;
         }
         g->out = O(NULL);
#if DEBUG 
         g->name = NULL;
#endif
#ifdef PRODUCE_CODE
         if (HAS_FLAG(g, f_UNINIT)) {
             printf("UNINIT %p\n",g);
         }
         if(!(g->in_a == 0 || (g->in_a >= heap_start && g->in_a < heap_end))) {
             printf("FAIL %p, %x\n",g, g->in_a);
         }
#ifndef SOL_DUMP
         assert(!HAS_FLAG(g, f_UNINIT));
         assert(g->in_a == 0 || (g->in_a >= heap_start && g->in_a < heap_end));
         assert(g->in_b == 0 || (g->in_b >= heap_start && g->in_b < heap_end));
#endif
#endif
     }
#ifdef PRODUCE_CODE
     //printf("heap at %p\n", g_heap.memory);
     //__builtin_debugtrap();
#endif

     FILE* f = fopen(file,"w");
     assert_m(f != NULL, "Unable to open file to save heap");

     fwrite(info, sizeof(CircutInfo), 1, f);

     size_t size_left = g_heap.size * sizeof(Gate);
     void* ptr = g_heap.memory;
     while (size_left > 0) {
         size_t did = fwrite(ptr, 1, size_left, f);
         size_left -= did;
         ptr += did;
     }
     fclose(f);
     printf("Gate heap saved to %s\n", file);
}

CircutInfo* load_circuit(char* file) {
    assert(g_heap.size == 0);

    FILE* f = fopen(file, "r");
    assert_m(f != NULL, "Could not open program file");

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);

    fseek(f, 0, SEEK_SET);

    CircutInfo* info = calloc(1, sizeof(CircutInfo));
    size_t meta_len = 0;
    meta_len += fread(info, 1, sizeof(CircutInfo), f);
    len -= meta_len;
    assert(len % sizeof(Gate) == 0);

    if (len >= g_heap.alloc_size_bytes - 1) {
        size_t new_amt = (len & ~0xfff);
        void* new_page = (void*)((uintptr_t)(g_heap.memory) + g_heap.alloc_size_bytes);
        new_page = mmap(new_page, new_amt, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        assert(new_page != NULL);
        g_heap.alloc_size_bytes += new_amt;
    }

    assert(len < g_heap.alloc_size_bytes - 1);

    size_t size_left = len;
    void* ptr = g_heap.memory;
    while (size_left > 0) {
        size_t did = fread(ptr, 1, size_left, f);
        size_left -= did;
        ptr += did;
    }
    fclose(f);
    g_heap.size = len / sizeof(Gate);

#ifdef PRODUCE_CODE
    printf("heap at %p\n", g_heap.memory);
#endif
   //__builtin_debugtrap();

    return info;
}

BitSet make_increment(BitSet in, Gate* one) {
    Gate* c = one;
    Gate** out = calloc(in.bits, sizeof(Gate*));
    for (uint8_t i=0; i<in.bits; i++) {
        Gate* c_o;
        out[i] = make_half_adder(c, in.wires[i], &c_o);
        c = c_o;
    }
    return BS(in.bits, out);
}

typedef struct decodedinst {
    Gate* bad_memory;
    Gate* halt;
    Gate* do_read;
    Gate* do_output;
    Gate* give_flag;
    Gate* start;

    Gate* do_jump; // If true, jump to address
    Gate* jump_if_z;
    BitSet jump_addr; // 4 bit address 

    Gate* do_write; // Write to reg A 
    Gate* b_or_const; // Constant value or b for alu b input
    BitSet alu_op; // 2 bits
    BitSet reg_a_sel;
    BitSet reg_b_sel;
} DecodedInstruction;

#ifdef INCLUDE_INST_DECODE
DecodedInstruction* decode_instruction(BitSet inst, uint8_t* transpose) {
    const uint8_t inst_bits = 8;
    const uint8_t pc_bits = MEM_ADDR_BITS;

    assert_h(inst.bits >= inst_bits, "Not enough bits for decoding");

    Gate** t_inst_wires = calloc(sizeof(Gate*), inst.bits);
    for (int i=0; i<inst.bits; i++) {
        t_inst_wires[i] = inst.wires[transpose[i]];
        //t_inst_wires[transpose[i]] = inst.wires[i];
        //t_inst_wires[i] = inst.wires[i];
    }

    // Instruction bitformat
    // | 1 | ALU Instruction 
    // | x | B or const
    // | x | Alu Op 0
    // | x | Alu Op 1
    // | x | Reg A 0 (also output)
    // | x | Reg A 1
    // | x | Reg B 0
    // | x | Reg B 1
    //
    // | 0 | Jump Instruction
    // | 1 | 
    // | x | If zero
    // | x | 
    // | x | Inst Addr
    // | x | ...
    // | x | ...
    // | x | ...
    //
    // | 0 | Control Instruction
    // | 0 | 
    // | x | Start
    // | x | Input
    // | x | Output
    // | x | Flag
    // | x | Halt
    // | x |

    DecodedInstruction* di = calloc(1, sizeof(DecodedInstruction));

    // === CTL OP ===
    Gate* is_ctl = AND(NOT(t_inst_wires[0]), NOT(t_inst_wires[1]));
    di->start = AND(is_ctl, t_inst_wires[2]);
    di->do_read = AND(is_ctl, t_inst_wires[3]);
    di->do_output = AND(is_ctl, t_inst_wires[4]);
    di->give_flag = AND(is_ctl, t_inst_wires[5]);
    di->halt = AND(is_ctl, t_inst_wires[6]);
    di->bad_memory = AND(is_ctl, t_inst_wires[7]);
    
    // === JMP OP ===
    di->do_jump = AND(NOT(t_inst_wires[0]), t_inst_wires[1]);
    di->jump_if_z = t_inst_wires[2];
    di->jump_addr = BS(pc_bits, t_inst_wires+3);
    assert(pc_bits+3 <= inst_bits);

    // === ALU OP ===
    di->do_write = t_inst_wires[0];
    di->b_or_const = t_inst_wires[1];
    di->alu_op = BS(2, t_inst_wires+2);

    // Reg OP
    di->reg_a_sel  = BS(2, t_inst_wires+4);
    di->reg_b_sel  = BS(2, t_inst_wires+6);

    return di;
}
#endif

void make_triangle(char* out_name) {
    //GateSet* ts = make_set(NULL);

    uint8_t width = 5;

    // We need 2 registers to keep the current x and y values
    // We need an adder to increment both
    // carry_out will tell use we hit the end of the line and to inc the out again
    //
    RegBank constants = make_readonly_memory(1, width);
    BitSet const_w_1 = constants.regs[0];
    set_value_bitset(const_w_1,1);

    Gate* const_1_1 = MEMORY_with_value(NULL, 1);
    Gate* const_1_0 = MEMORY_with_value(NULL, 0);
    //push_set(ts, const_1_1);
    //push_set(ts, const_1_0);

    Gate* sanity1 = OUTPUT(XOR(const_1_1,const_1_0));
    SET_FLAG(sanity1, f_SANITY, 1);
    Gate* sanity2 = OUTPUT(NOT(XOR(const_1_1,const_1_1)));
    SET_FLAG(sanity2, f_SANITY, 1);


    // === Two registers ===
#ifdef PRODUCE_CODE
    Gate* which_reg = PLACEHOLDER();
#else
    Gate* which_reg = NULL;
#endif
    BitSet reg_input = make_placeholder_bitset(width);

    RegBank regs = make_register_bank(2, width, BS(1,&which_reg), const_1_1, reg_input);
    //push_set_bitset(ts, regs.regs[0]);
    //push_set_bitset(ts, regs.regs[1]);

    BitSet reg_out = mux_two(regs.regs[0], regs.regs[1], which_reg);

    // === Perform increment ===
    Gate* carry_in = const_1_0;
    BitSet add_a = reg_out;
    BitSet add_b = const_w_1;
    Gate* carry = carry_in;

    BitSet add_out = make_full_adder_bitset(add_a, add_b, carry_in, &carry);

    /*
    for (uint8_t i=0; i<width; i++) {
        Gate* next_carry = NULL;
        add_out.wires[i] = make_full_adder(add_a.wires[i], add_b.wires[i], carry, &next_carry);
        carry = next_carry;
    }
    */


#ifdef PRODUCE_CODE
    resolve_placeholder_bitset(reg_input, add_out);
#endif

    Gate* which_reg_buffer = MEMORY_with_value(carry, 0);
#ifdef PRODUCE_CODE
    resolve_placeholder(which_reg, which_reg_buffer);
#endif

    Gate* end_program = OUTPUT(AND(carry, which_reg_buffer));

    Gate* new_line = carry;

    // (x & y) ^ x
    // === Decide triangle output ===
    BitSet in_a = regs.regs[0];
    BitSet in_b = regs.regs[1];

    Gate** matches = calloc(width, sizeof(Gate*));
    for (uint8_t i=0; i<width; i++) {
        Gate* and = AND(in_a.wires[i], in_b.wires[i]);
        Gate* match = NOT(XOR(in_a.wires[i], and));
        matches[i] = match;
    }

    Gate* char_on = make_bit_andor(BS(width, matches),1);

    // === Decide ouput char ===
    RegBank chars = make_readonly_memory(3, 8);
    set_value_bitset(chars.regs[0],' ');
    set_value_bitset(chars.regs[1],'A');
    set_value_bitset(chars.regs[2],'\n');

    BitSet chosen_char = mux_two(chars.regs[0], chars.regs[1], char_on);
    BitSet char_or_line = mux_two(chosen_char, chars.regs[2], new_line);

    BitSet out_char = make_output_bitset(char_or_line);

    Gate* do_char_write = const_1_1;

    CircutInfo info = { 0 };
    info.max_cycles = 2000;
    for (uint8_t i=0; i<8; i++) {
        info.out_char[i] = O(out_char.wires[i]);
    }
    info.do_out = O(do_char_write);
    info.halt = O(end_program);

    //run_circuit_with_info(&info, ts);
    //make_graphvis("/src/triangle.gv");
#ifdef PRODUCE_CODE
    save_gate_heap(out_name, &info);
#else
    save_gate_heap("/data/triangle.bin", &info);
#endif

    // Testing
    /*

    reset_circuit((Gate*)ts);

    puts("Starting to evaluate circuit");
    uint8_t end = 0;
    do  {
        uint64_t r0_b = get_value_bitset(regs.regs[0]);
        uint64_t r1_b = get_value_bitset(regs.regs[1]);

        run_circuit((Gate*)ts);

        uint8_t co = get_value_bitset(out_char);
        end = get_value(end_program);
        uint8_t b_b = get_value(which_reg_buffer);

        uint8_t carry_v = get_value(carry);

        _reset_circuit((Gate*)ts, 0);

        uint64_t r0_a = get_value_bitset(regs.regs[0]);
        uint64_t r1_a = get_value_bitset(regs.regs[1]);
        uint8_t b_a = get_value(which_reg_buffer);

        / *
        printf("%lx,%lx -> %lx,%lx | %u->%u | carry=%u | char=%x | exit=%u\n",
                r0_b, r1_b, r0_a, r1_a,
                b_b, b_a,
                carry_v, co, end);
        * /
        printf("%c", co);
        //sleep(1);
    } while(end == 0);
    */
}

#ifdef PRODUCE_CODE
typedef struct label {
    int ind;
    int addr;
    struct label* next;
} Label;
Label* make_label() {
    Label* l = malloc(sizeof(struct label));
    l->ind = -1;
    l->addr = -1;
    l->next = NULL;
    return l;
}
void place_label(Label* l, int a, uint8_t* mem) {
    l->addr = a;
    if (l->ind != -1) {
        uint8_t v = mem[l->ind];
        v &= 0b111;
        v |= a<<3;
        mem[l->ind] = v;
    }
    if (l->next) {
        place_label(l->next, a, mem);
        free(l->next);
        l->next = NULL;
    }
    l->ind = -1;
}
uint8_t use_label(Label* l, int a) {
    if (l->addr != -1)
        return l->addr;
    if (l->next != NULL)
        return use_label(l->next, a);
    if (l->ind != -1) {
        l->next = make_label();
        return use_label(l->next, a);
    }
    l->ind = a;
    return 0;
}
#endif
#ifdef PRODUCE_CODE
uint8_t do_transpose(uint8_t in, uint8_t* transpose) {
    uint8_t bits[8] = { 0 };
    for (int i=0; i<8; i++) {
        bits[transpose[i]] = (in>>i)&1;
    }
    uint8_t out = 0;
    for (int i=0; i<8; i++) {
        if (bits[i] == 0)
            continue;
        out |= (1 << i);
    }
    return out;
}
void cpu_chal(char* out_name, int prog) {
    GateSet* ts = make_set(NULL);

    uint8_t width = 8;

    uint8_t __ci = 0;
    RegBank constants = make_readonly_memory(4, width);
    for (uint8_t i=0; i<4; i++) {
        push_set_bitset(ts,constants.regs[i]);
        set_value_bitset(constants.regs[i], 0);
    }

    Gate* const_1_1 = MEMORY_with_value(NULL, 1);
    Gate* const_1_0 = MEMORY_with_value(NULL, 0);
    push_set(ts, const_1_1);
    push_set(ts, const_1_0);

#define CONST_X(v) push_set(ts, MEMORY_with_value(NULL, v))

    //SET_FLAG(OUTPUT((XOR(CONST_X(1),CONST_X(1)))), f_SANITY, 1);
    //SET_FLAG(OUTPUT((XOR(CONST_X(1),CONST_X(1)))), f_SANITY, 1);
    //SET_FLAG(OUTPUT((XOR(CONST_X(1),CONST_X(1)))), f_SANITY, 1);
    //SET_FLAG(OUTPUT((XOR(CONST_X(1),CONST_X(1)))), f_SANITY, 1);


    Gate* sanity1 = OUTPUT(XOR(CONST_X(1),CONST_X(0)));
    SET_FLAG(sanity1, f_SANITY, 1);
    Gate* sanity2 = OUTPUT(XOR(CONST_X(1),CONST_X(0)));
    SET_FLAG(sanity2, f_SANITY, 1);
    Gate* sanity3 = OUTPUT(XOR(CONST_X(1),CONST_X(0)));
    SET_FLAG(sanity3, f_SANITY, 1);
    Gate* sanity4 = OUTPUT(XOR(CONST_X(1),CONST_X(0)));
    SET_FLAG(sanity4, f_SANITY, 1);

    // === 8 Bit Registers ===
    uint8_t num_reg = 4;
    uint8_t reg_sel_bits = 2;
    BitSet reg_to_write = make_placeholder_bitset(reg_sel_bits);
    BitSet reg_write_val = make_placeholder_bitset(width);
    Gate* do_reg_write = PLACEHOLDER();

    RegBank regs = make_register_bank(num_reg, width, reg_to_write, do_reg_write, reg_write_val);
    for (uint8_t i=0; i<num_reg; i++) {
        push_set_bitset(ts, regs.regs[i]);
    }


    uint8_t inst_bits = 8;
    assert(inst_bits >= 8);
    uint8_t pc_bits = MEM_ADDR_BITS;

    // Using a "memory device" instead
    //RegBank inst_memory = make_readonly_memory(1<<pc_bits, inst_bits);
    //BitSet inst = mux_register_bank(inst_memory, pc);

    BitSet inst = make_input_bitset(inst_bits);
    push_set_bitset(ts, inst);
    set_value_bitset(inst, 0);

    uint8_t* transpose = calloc(sizeof(uint8_t), width);
#ifdef SWAP_INST_BITS
    if (prog == 0) {
#endif
        transpose[0] = 0;
        transpose[1] = 1;
        transpose[2] = 2;
        transpose[3] = 3;
        transpose[4] = 4;
        transpose[5] = 5;
        transpose[6] = 6;
        transpose[7] = 7;
#ifdef SWAP_INST_BITS
    } else {
        transpose[0] = 2;
        transpose[1] = 1;
        transpose[2] = 0;
        transpose[3] = 3;
        transpose[4] = 4;
        transpose[5] = 5;
        transpose[6] = 6;
        transpose[7] = 7;
    }
#endif
    DecodedInstruction* di = decode_instruction(inst, transpose);

    BitSet reg_a = mux_register_bank(regs, di->reg_a_sel);
    BitSet reg_b = mux_register_bank(regs, di->reg_b_sel);
    BitSet const_b = mux_register_bank(constants, di->reg_b_sel);

    BitSet val_a = reg_a;
    BitSet val_b = mux_two(reg_b, const_b, di->b_or_const);

    ALU alu = make_alu(di->alu_op, val_a, val_b);

    resolve_placeholder_bitset(reg_write_val, alu.out);
    resolve_placeholder_bitset(reg_to_write, di->reg_a_sel);
    resolve_placeholder(do_reg_write, di->do_write);


    Gate* zero_flag = REGISTER(di->do_write, alu.zero);
    push_set(ts, zero_flag);

    // !jz || (jz && z) == !(jz && !z)
    // 0 0 1
    // 0 1 1
    // 1 1 1
    // 1 0 0
    // -
    // 0 1 1
    // 0 0 1
    // 1 0 1
    // 1 1 0
    Gate* do_jump = AND(di->do_jump, NAND(di->jump_if_z, NOT(zero_flag)));

    BitSet pc = make_placeholder_bitset(pc_bits);

    BitSet pc_inc = make_increment(pc, const_1_1);

    BitSet new_pc = mux_two(pc_inc, di->jump_addr, do_jump);

    BitSet pc_reg = make_memory_bitset(new_pc);
    push_set_bitset(ts, pc_reg);
    set_value_bitset(pc_reg, 0xffff);


    resolve_placeholder_bitset(pc, pc_reg);

    //BitSet out = make_output_bitset(alu.out);
    //Gate* carry = OUTPUT(alu.carry);
    //Gate* zero = OUTPUT(alu.zero);
    //Gate* over = OUTPUT(alu.overflow);

    Gate* halt_flag = OUTPUT(di->halt);
    Gate* bad_memory_flag = OUTPUT(di->bad_memory);
    Gate* read_flag = OUTPUT(di->do_read);
    Gate* output_flag = OUTPUT(di->do_output);
    Gate* give_flag_flag = OUTPUT(di->give_flag);

    // Check that we ran the start instruction first
    Gate* decode_sanity = REGISTER(di->start, const_1_1);
    push_set(ts, decode_sanity);
    Gate* decode_sanity_out = OUTPUT(NOT(AND(NOT(decode_sanity), pc_inc.wires[1])));
    SET_FLAG(decode_sanity_out, f_SANITY, 1);
    SET_FLAG(decode_sanity_out, f_SANITY_DECODE, 1);

    // Ask device for next PC
    BitSet pc_out = make_output_bitset(new_pc);



    CircutInfo cinfo = { 0 };
    cinfo.halt = O(halt_flag);
    cinfo.halt_bad_memory = O(bad_memory_flag);

    for (uint8_t i=0; i<8; i++) {
        cinfo.in_char[i] = O(regs.regs[0].wires[i]);
    }
    cinfo.do_in = O(read_flag);
    for (uint8_t i=0; i<8; i++) {
        cinfo.out_char[i] = O(regs.regs[3].wires[i]);
    }
    cinfo.do_out = O(output_flag);
    cinfo.give_flag = O(give_flag_flag);
    for (uint8_t i=0; i<MEM_ADDR_BITS; i++) {
        cinfo.mem_addr[i] = O(pc_out.wires[i]);
    }
    for (uint8_t i=0; i<inst_bits; i++) {
        cinfo.mem_char[i] = O(inst.wires[i]);
    }

    uint8_t ma = 0xff;
#define r2b(a) (((a>>1)&1)|((a&1)<<1))
#define TRANSPOSE(x) (do_transpose(x, transpose))
#define I(v) ma++;cinfo.memory[ma]=(TRANSPOSE(v));printf("%u=%x\n",ma,v);
#define i_ADD(a,b) I(0b1001 | (a<<4) | (b<<6))
//#define i_SUB(a,b) I(0b1101 | (a<<4) | (b<<6))
#define i_AND(a,b) I(0b1101 | (a<<4) | (b<<6))
#define i_XOR(a,b) I(0b0101 | (a<<4) | (b<<6))
#define i_ADD_C(a,b) I(0b1011 | (a<<4) | (b<<6))
//#define i_SUB_C(a,b) I(0b1111 | (a<<4) | (b<<6))
#define i_AND_C(a,b) I(0b1111 | (a<<4) | (b<<6))
#define i_XOR_C(a,b) I(0b0111 | (a<<4) | (b<<6))
#define i_ROT5(a)    I(0b0001 | (a<<4) | (a<<6))
#define i_JMP(a)   I( 0b010 | (a<<3))
#define i_JZ(a)    I( 0b110 | (a<<3))
#define i_HLT_BM()   I(0b11000100)
#define i_HLT()   I(0b01000100)
#define i_IN()    I(0b00001000)
#define i_OUT()   I(0b00010000)
#define i_FLAG()  I(0b01100000)
#define i_START() I(0b00000100)
#define i_NOP()   I(0b00000000)
#define TO_LABEL(name) use_label(name, ma)
#define LABEL(name) place_label(name, ma+1,cinfo.memory);



    if (prog == 0) {
        // Flag password
        set_value_bitset(constants.regs[0], 0x3f);
        set_value_bitset(constants.regs[1], 0xd5); //0xa2
        set_value_bitset(constants.regs[2], 0x54); //0x2a
        set_value_bitset(constants.regs[3], 0);

        Label* good_first_char = make_label();
        Label* good_hash1 = make_label();
        Label* good_hash2 = make_label();
        Label* good_last_char = make_label();
        Label* good_length = make_label();
        Label* exit = make_label();
        Label* exit2 = make_label();
        Label* exit3 = make_label();
        Label* loop = make_label();
        Label* loop_end = make_label();
        Label* good_consts = make_label();

        i_START();
        i_XOR_C(0,3);
        i_JZ(TO_LABEL(good_consts)); // Check if null
        //i_HLT();
        i_HLT_BM();


        LABEL(good_consts);
        i_IN();
        i_XOR_C(0,0);
        //i_SUB_C(0,0); // if (a ^ 0x3f == 0)
        i_JZ(TO_LABEL(good_first_char)); // Check if null
        i_HLT();

        LABEL(good_first_char);
        i_ADD_C(3,0);
        LABEL(loop);
        i_IN();
        i_XOR_C(0,3); // if (a ^ 0 == 0)
        //i_SUB_C(0,3);
        i_JZ(TO_LABEL(exit)); // Check if null
        i_ADD_C(1,0);

        i_ROT5(2);
        i_ROT5(3);

        i_ADD(2,0);
        i_ADD(3,0);

        i_ROT5(1);
        i_JZ(TO_LABEL(loop_end));
        i_JMP(TO_LABEL(loop));

        LABEL(loop_end);
        i_IN();
        //i_SUB_C(0,0);
        // needed to do the jump
        i_XOR_C(0,0); // if (a ^ 0x3f == 0)
        i_JZ(TO_LABEL(good_last_char));
        LABEL(exit)
        i_JMP(TO_LABEL(exit));

        LABEL(good_last_char);
        /*
        i_IN();
        i_JZ(TO_LABEL(good_length)); // Make sure we only sent enough chars
        i_HLT();

        LABEL(good_length);
        */
        //i_SUB_C(2,1);
        i_XOR_C(2,1); // if (a ^ c1 == 0)
        i_JZ(TO_LABEL(good_hash1));
        i_JMP(TO_LABEL(exit)); //i_HLT();

        LABEL(good_hash1);
        //i_SUB_C(3,2);
        i_XOR_C(3,2); // if (a ^ c2 == 0)
        i_JZ(TO_LABEL(good_hash2));
        i_JMP(TO_LABEL(exit)); //i_HLT();

        LABEL(good_hash2);
        i_FLAG();

        cinfo.max_cycles = 300;
        cinfo.max_run_time = 30;
    } else if (prog == 1) {
        // Triangle
        set_value_bitset(constants.regs[0], 'V');
        set_value_bitset(constants.regs[1], ' '); //0xa2
        set_value_bitset(constants.regs[2], '\n'); //0x2a
        set_value_bitset(constants.regs[3], 1);

        Label* outer_loop = make_label();
        Label* inner_loop = make_label();
        Label* next_line = make_label();
        Label* done = make_label();
        Label* yes_output = make_label();
        Label* no_output = make_label();
        Label* do_out = make_label();

        i_START();
        LABEL(outer_loop);
        LABEL(inner_loop);

        const uint8_t LEN_IND = 1;

        i_XOR(3,3);

        // Determin if lit
        i_XOR(2,2); // r2 = 0
        i_XOR(2,0); // r2 = r0
        i_AND(2,1); // r2 = r2 & r1
        i_XOR(2,1); // r2 = r2 ^ r1
        i_JZ(TO_LABEL(yes_output));

        LABEL(no_output);
        i_XOR_C(3,1); // Output ' '
        i_JMP(TO_LABEL(do_out));

        LABEL(yes_output);
        i_XOR_C(3,0); // Output 'A'

        LABEL(do_out);
        i_OUT();

        i_ADD_C(0, 3); // x + 1
        i_XOR_C(0, LEN_IND); // if (x ^ 0x20 == 0)
        i_JZ(TO_LABEL(next_line));
        i_XOR_C(0, LEN_IND); // Undo xor
        i_JMP(TO_LABEL(inner_loop));

        LABEL(next_line);
        i_XOR(3,3);
        i_XOR_C(3,2);
        i_OUT();

        i_ADD_C(1, 3); // y + 1
        i_XOR_C(1, LEN_IND); // if (y ^ 0x20 == 0)
        i_JZ(TO_LABEL(done));
        i_XOR_C(1, LEN_IND); // Undo xor
        i_JMP(TO_LABEL(outer_loop));

        LABEL(done);

        i_HLT();
        /*

        // r0 = x
        // r1 = y

        LABEL(loop);
        i_XOR(3,3);

        */

        //i_FLAG();
        cinfo.max_cycles = 100000;
        cinfo.max_run_time = 3000;
    }

    printf("Using 0x%x bytes of instructions\n",ma);
    assert(ma <= (1 << MEM_ADDR_BITS));


#ifdef DEBUG_CPU
    cinfo.pc = pc_out;
    cinfo.regs = regs;
#endif

    //run_circuit_with_info(&cinfo, ts);
    //make_graphvis("/src/password_for_flag.gv");
    save_gate_heap(out_name, &cinfo);
#if 0
    CircutInfo cinfo;
    puts("PROPRIETARY CODE SCRUBBED");
    asm("brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;");
    asm("brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;brk 1;");

    save_gate_heap("/data/password_for_flag.bin", &cinfo);
#endif
}
#endif
#ifdef PRODUCE_CODE
#undef CONST_X
void test_dmp(char* out_name) {
    /*
    BitSet sel = make_input_bitset(2);
    Gate* do_w = INPUT();
    BitSet val = make_input_bitset(8);

    RegBank regs = make_register_bank(4, 8, sel, do_w, val);
    */

    /*
    RegBank regs = make_readonly_memory(4,8);
    BitSet sel = make_input_bitset(2);

    BitSet sel_reg = mux_register_bank(regs, sel);
    BitSet val = make_output_bitset(sel_reg);
    */
    /*
    BitSet inst = make_input_bitset(8);
    DecodedInstruction* di = decode_instruction(inst);
    OUTPUT(di->halt);
    OUTPUT(di->give_flag);
    OUTPUT(di->do_read);
    OUTPUT(di->do_jump);
    OUTPUT(di->jump_if_z);
    make_output_bitset(di->jump_addr);
    OUTPUT(di->do_write);
    OUTPUT(di->b_or_const);
    make_output_bitset(di->alu_op);
    make_output_bitset(di->reg_a_sel);
    make_output_bitset(di->reg_b_sel);
    
    

    
    

    CircutInfo info = { 0 };
    //run_circuit_with_info(&info, ts);
    //make_graphvis("/src/triangle.gv");
    save_gate_heap(out_name, &info);
    */
}
#endif
#ifdef PRODUCE_CODE
void test_alu(char* out_name) {
    //puts("=== TEST ALU ===");

    GateSet* ts = make_set(NULL);

    const uint64_t width = 8;

    BitSet in_a = make_input_bitset(width);
    push_set_bitset(ts, in_a);
    BitSet in_b = make_input_bitset(width);
    push_set_bitset(ts, in_b);

    BitSet op = make_input_bitset(2);

    ALU alu = make_alu(op, in_a, in_b);

    BitSet out = make_output_bitset(alu.out);
    Gate* carry = OUTPUT(alu.carry);
    Gate* zero = OUTPUT(alu.zero);
    Gate* over = OUTPUT(alu.overflow);

#ifdef PRODUCE_CODE
    CircutInfo info = { 0 };
    info.max_cycles = 2000;
    info.halt = O(alu.out.wires[0]);

    //run_circuit_with_info(&info, ts);
    //make_graphvis("/src/triangle.gv");
    //save_gate_heap(out_name, &info);
#endif

    for (uint8_t i=0; i<20; i++) {
        uint64_t mask = (1lu << width) - 1;
        uint64_t a = random() & mask;
        uint64_t b = random() & mask;
        reset_circuit((Gate*)ts);

        set_input_bitset(op, i%4);
        set_input_bitset(in_a, a);
        set_input_bitset(in_b, b);
        uint64_t r;
        if (i%4 == alu_SHIFT) {
            continue;
        }
        switch(i%4) {
        case alu_SHIFT:
            r = a & b;
            break;
        case alu_XOR:
            r = a ^ b;
            break;
        case alu_ADD:
            r = a + b;
            break;
        case alu_AND:
            r = a & b;
            break;
        };
        r = r & mask;

        run_circuit((Gate*)ts);

        uint64_t v = get_value_bitset(out);
        //printf("out %lx c=%u z=%u o=%u\n", v, get_value(carry), get_value(zero), get_value(over));
        assert(r == v);

    }

    puts("=== TEST OK ===");
}
#endif

void seed_rand() {
    FILE* f = fopen("/dev/urandom","r");
    assert_m(f != NULL, "Unable to open /dev/urandom");
    uint32_t v = 0;
    fread(&v, 1, sizeof(v), f);
    srand(v);
}

void handle_alarm(int signum){
  puts("Timeout hit! Exiting...");
  exit(-1);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    reset_pac();

    init_gate_heap();

    /*
    GateRing* r = make_gate_ring(4);
    gate_ring_push(r, INPUT());
    gate_ring_pop(r);
    gate_ring_push(r, INPUT());
    gate_ring_push(r, INPUT());
    gate_ring_push(r, INPUT());
    gate_ring_push(r, INPUT());
    gate_ring_push(r, INPUT());

    gate_ring_pop(r);
    gate_ring_pop(r);
    gate_ring_pop(r);
    gate_ring_pop(r);
    gate_ring_pop(r);
    // */

    /*
    test_nand();
    test_and();
    test_or();
    test_xor();
    test_half_adder();
    test_full_adder();
    // */
    //test_decoder();
    //test_register();
    //test_register_bank();
    //test_alu();
    //test_placeholders();

    //*
    //

    // */


#ifdef PRODUCE_CODE
    if (argc < 3) {
        puts("./build_prog <to_build> <program file>");
        return -1;
    }
    uint32_t hash = 1337;
#ifdef PROG_RAND
    for (size_t i=0; i<strlen(argv[2]); i++) {
        hash = ((hash << 5) + hash) + argv[2][i];
    }
#endif
    srand(hash); // Make the files reproducible
    if (!strcmp(argv[1], "triangle")) {
        cpu_chal(argv[2], 1);
    } else if (!strcmp(argv[1], "flag")) {
        cpu_chal(argv[2], 0);
    } else if (!strcmp(argv[1], "alu")) {
        test_alu(argv[2]);
    } else if (!strcmp(argv[1], "dmp")) {
        test_dmp(argv[2]);
    } else {
        puts("Unknown circuit");
        assert(0);
    }
    printf("%lu gates, %lx mem, %lx max queue\n",
            g_num_nand_gates,
            g_heap.alloc_size_bytes,
            g_queue_depth
    );
#else
    seed_rand();
    signal(SIGALRM, handle_alarm);
    g_start_t = time(NULL);
    if (argc < 2) {
        puts("./run_prog <program file>");
        return -1;
    }
    printf("Loading program %s\n", argv[1]);
    CircutInfo* info = load_circuit(argv[1]);
    alarm(info->max_run_time);

    GateSet* sources = make_set(NULL);
    build_heap_backrefs(sources);
    puts("Starting program...");
    run_circuit_with_info(info, sources);
    time_t delta_t = time(NULL) - g_start_t;
    if (delta_t < 20) {
        sleep(20 - delta_t);
    }
    puts("Program halted");
#endif

    //*
    //do_add(0x4142434445464748, 0x4142434445464748);
    // */
    /*
    printf("%lu gates, %lx mem, %lx max queue\n",
            g_num_nand_gates,
            g_heap.alloc_size_bytes,
            g_queue_depth
    );
    */
    //load_circuit("/src/heap.bin");
    /*
    puts("Hello world! [enter]");
    

    uint64_t res = pac_sign(1, 2);
    printf("signed %p\n",res);
    uint64_t n_res = pac_verify(res, 2);
    printf("good ctx %p\n",n_res);
    n_res = pac_verify(res, 3);
    printf("bad ctx %p\n",n_res);

    reset_pac();
    n_res = pac_verify(res, 2);
    printf("good ctx %p\n",n_res);
    */
}
