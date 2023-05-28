// good firmware image, that authenticates itself successfully
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

int _read_syscall(int fd, char *buf, unsigned long long n);
int _write_syscall(int fd, char *buf, unsigned long long n);
int _recvmsg_syscall(int fd, struct msghdr *msg, int flags);
unsigned long _get_pc();

typedef struct __attribute__((__packed__)) {
	unsigned reserverd;
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
} sfm_get_identity_t;

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

void authenticate(int fd, int bank_idx, unsigned long pc, size_t len);

// NOTE: this must be the very first declared function for things
// to work end-to-end
#define TOTAL_LEN 0x2000
int _start(void) {
	unsigned long pc = _get_pc();
	pc &= ~0xfff;

	handshake(3);

	authenticate(3, 1, pc, TOTAL_LEN);

	int fds[2] = {0};
	if (send_establish_secure_io(3, 3, &fds) < 0)
	{
		return 1;
	}
	int std_in = fds[0];
	int std_out = fds[1];

	control_loop(3, std_in, std_out);

	_puts(std_out, "exiting...\n");
}

void authenticate(int fd, int bank_idx, unsigned long pc, size_t len) {

	unsigned long off = 0;
	for (off = 0; off < len; off += 1024) {
		send_integrity_update(fd, bank_idx, (unsigned char *)(pc + off), 1024);
	}
}

void _memcpy(unsigned char *dst, unsigned char *src, size_t n) {
	while (n-- > 0) { *dst++ = *src++; }
}

void _memset(unsigned char *dst, unsigned char x, size_t n) {
	while (n-- > 0) { *dst++ = x; }
}

size_t _strlen(unsigned char *s) {
	size_t i = 0;
	for (i = 0; s[i] != '\0'; i++);
	return i;
}

int _strcmp(unsigned char *s1, unsigned char *s2) {
	for (;*s1 != '\0'; s1++, s2++) {
		int result = (int)(*s1 - *s2);
		if (result) return result;
	}
	return *s2;
}

void _puts(int std_out, unsigned char *s) {
	_write_syscall(std_out, s, _strlen(s));
}

void tohex_char(unsigned char x, char *out) {
	unsigned char most =  (x >> 4) & 0xf;
	unsigned char least = x & 0xf;

	out[0] = most < 10 ? 0x30 + most : 0x41 + (most - 10);
	out[1] = least < 10 ? 0x30 + least : 0x41 + (least - 10);
}

void tohex_buf(unsigned char *in, size_t in_len, unsigned char *out) {
	size_t i = 0;
	for (i = 0; i < in_len; i++) tohex_char(in[i], &out[i*2]);
}

void handshake(int fd) {
	int cookie = 0;

	_read_syscall(fd, &cookie, sizeof(cookie));
	_write_syscall(fd, (char *)&cookie, sizeof(cookie));
}

size_t readline(int std_in, char *buf, size_t len)
{
	size_t pos = 0;
	for (;pos < len; pos++) {
		char cur = '\0';
		_read_syscall(std_in, &cur, sizeof(cur));
		if (cur == '\n') {
			buf[pos] = '\0';
			return pos;
		}
		buf[pos] = cur;
	}
	buf[pos-1] = '\0';
	return pos;
}

void do_quote(int fd, int std_out) {
	char quote_buf[512] = {0};
	send_attest_quote(fd, 0, &quote_buf, sizeof(quote_buf));

	unsigned char sig_digest_hex[512+1] = {0};
	tohex_buf(quote_buf, 256, sig_digest_hex);

	_puts(std_out, "Quote:\n");
	_puts(std_out, "  Sig: ");
	_puts(std_out, sig_digest_hex);
	_puts(std_out, "\n");

	size_t i = 0;
	unsigned char index_hex[3] = {0};
	unsigned char bank_hex[128+1] = {0};
	for (i = 0; i < 4; i++) {
		tohex_buf(&quote_buf[256+(i * 64)], 64, bank_hex);
		_puts(std_out, "  Bank ");
		tohex_char((unsigned char)i, index_hex);
		_puts(std_out, index_hex);
		_puts(std_out, ": ");
		_puts(std_out, bank_hex);
		_puts(std_out, "\n");
	}
}

void do_get_identity(int fd, int std_out) {
	char identity[512] = {0};

	send_get_identity(fd, &identity, sizeof(identity));

	// assumptions about all parameter sizes
	unsigned char e_hex[6+1] = {0};
	tohex_buf(identity, 3, e_hex);

	_puts(std_out, "Identity:\n");
	_puts(std_out, "  E: ");
	_puts(std_out, e_hex);
	_puts(std_out, "\n");

	unsigned char n_hex[512+1] = {0};
	tohex_buf(&identity[3], 256, n_hex);

	_puts(std_out, "  N: ");
	_puts(std_out, n_hex);
	_puts(std_out, "\n");
}

void do_certify(int fd, int std_out) {
	char certification[256 + 128] = {0};

	send_certify_object(fd, 0, &certification, sizeof(certification));

	unsigned char sig_digest_hex[512+1] = {0};
	tohex_buf(certification, 256, sig_digest_hex);

	_puts(std_out, "Ownership:\n");
	_puts(std_out, "  Sig: ");
	_puts(std_out, sig_digest_hex);
	_puts(std_out, "\n");

	unsigned char serial_hex[16+1] = {0};
	tohex_buf(&certification[256], 8, serial_hex);

	_puts(std_out, "  Serial: ");
	_puts(std_out, serial_hex);
	_puts(std_out, "\n");

	unsigned char time_hex[16+1] = {0};
	tohex_buf(&certification[256+8], 8, time_hex);
	_puts(std_out, "  Timestamp: ");
	_puts(std_out, time_hex);
	_puts(std_out, "\n");

	char *cert_str = &certification[272];
	cert_str += 2;

	size_t i = 0;
	for(;i<_strlen(cert_str);i++) {
		if (cert_str[i] == ',') {
			cert_str[i] = '\0';
			break;
		}
	}
	char *owner_name = cert_str;
	char *device_name = &cert_str[i+1] + 3;

	_puts(std_out, "  Owner Name: ");
	_puts(std_out, owner_name);
	_puts(std_out, "\n");

	_puts(std_out, "  Device Name: ");
	_puts(std_out, device_name);
	_puts(std_out, "\n");
}

void control_loop(int sfm_fd, int std_in, int std_out)
{
	_puts(std_out, "Attested core booted...\n");

	while (1) {
		short prompt_c = 0x2023;
		_write_syscall(std_out, &prompt_c, sizeof(prompt_c));

		char line[20] = {0};
		readline(std_in, &line, sizeof(line));

		if (!_strcmp(line, "exit")) {
			return;
		}
		if (!_strcmp(line, "identity")) {
			do_get_identity(sfm_fd, std_out);
		}
		if (!_strcmp(line, "quote")) {
			do_quote(sfm_fd, std_out);
		}
		if (!_strcmp(line, "certify")) {
			do_certify(sfm_fd, std_out);
		}
	}
}

int send_integrity_update(int fd, 
			  int bank_idx,
			  unsigned char *content_start,
			  size_t len) {

	sfm_integrity_update_t msg;

	msg.header.cmd = 1;

	msg.bank_index = bank_idx;

	_memset(msg.payload, '\x00', 1024);
	_memcpy(msg.payload, content_start, len);

	_write_syscall(fd, &msg, sizeof(msg));

	int ret = 0;
	_read_syscall(fd, &ret, sizeof(ret));
	return ret;
}

int send_get_identity(int fd, unsigned char *identity, size_t identity_len) {
	sfm_get_identity_t msg;

	msg.header.cmd = 0;

	_write_syscall(fd, &msg, sizeof(msg));

	_read_syscall(fd, identity, identity_len);

}

int send_attest_quote(int fd, int alg_id, char *quote_buf, size_t buf_size) {
	sfm_attest_quote_t msg;

	msg.header.cmd = 7;

	msg.alg_id = alg_id;

	_write_syscall(fd, &msg, sizeof(msg));
	
	_read_syscall(fd, quote_buf, buf_size);
}


void send_certify_object(int fd, int obj_idx, char *cert, size_t cert_len) {
    sfm_certify_object_t msg;

    msg.header.cmd = 6;

    msg.object_index = obj_idx;

    _write_syscall(fd, &msg, sizeof(msg));

    _read_syscall(fd, cert, cert_len);
}

int send_establish_secure_io(int fd, int flags, int *fds) {
	sfm_establish_secure_io_t msg;

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
