#include "ifuckup.h"

#define size_t unsigned long

#define PROGSIZE (0x0804c000-0x08048000)
#define EXECSIZE (0x0804b000-0x08048000)
#define DATASIZE (PROGSIZE-EXECSIZE)

static unsigned int CurAlloc, CurStackAlloc;
static unsigned int CurRandom;
static unsigned int StackSize;

static WELLStruct *WELLctx;

void ConvertValToHex(unsigned int Val, char *Buffer)
{
	int x;
    for(x = 8; x; x--) {
      Buffer[x-1] = (Val & 0xf) + 0x30;
      if(Buffer[x-1] > '9')
        Buffer[x-1] += 0x27;
      Val >>= 4;
    }
}

unsigned int my_syscall(int eax, int ebx, int ecx, int edx, int esi, int edi, int ebp)
{
        int Result;

        __asm__("push %%ebx\n"
                "push %%edi\n"
                "push %%ebp\n"
                "mov %1, %%eax\n"
                "mov %2, %%ebx\n"
                "mov %3, %%ecx\n"
                "mov %4, %%edx\n"
                "mov %5, %%esi\n"
                "mov %6, %%edi\n"
                "mov %7, %%ebp\n"
                "int $0x80\n"
                "pop %%ebp\n"
                "pop %%edi\n"
                "pop %%ebx\n"
                : "=a" (Result)
                : "m" (eax), "m" (ebx), "m" (ecx), "m" (edx), "m" (esi), "m" (edi), "m" (ebp)
                : "ecx", "edx", "esi"
        );

        return Result;
}

inline void send_string(char *msg)
{
	size_t len;
	char *msg_t = msg;
	for(len = 0; *msg_t; len++, msg_t++) {}
	f_write(1, msg, len);
}

void f_memcpy(void *out, void *in, size_t len)
{
	unsigned long *out_t = (unsigned long *)out;
	unsigned long *in_t = (unsigned long *)in;
	unsigned char *out_b, *in_b;

	unsigned long len_t = len & ~(sizeof(unsigned long) - 1);

	len -= len_t;
	while(len_t)
	{
		*out_t = *in_t;
		out_t++;
		in_t++;
		len_t -= sizeof(unsigned long);
	}

	out_b = (unsigned char *)out_t;
	in_b = (unsigned char *)in_t;
	while(len)
	{
		*out_b = *in_b;
		out_b++;
		in_b++;
		len--;
	}
}

void f_memset(void *out, unsigned char in, size_t len)
{
	unsigned char *out_b = (unsigned char *)out;
	while(len)
	{
		*out_b = in;
		out_b++;
		len--;
	}
}

int recv_until(char *buffer, int size, char c )
{
	int readbytes = 0;
	int counter = 0;
	char recvchar = 0;
	
	do
	{
		readbytes = f_read(0, &recvchar, 1);
		if(readbytes == -1)
			continue;
		
		if ( recvchar == c )
			break;
		
		buffer[counter] = recvchar;
		
		counter++;
	} while ( (counter < size) && (recvchar != c) );

	//randomize on number of bytes that come in
	for(readbytes = 0; readbytes < (counter-1); readbytes++)
		WELLRNG512a(&WELLctx[0]);

	RandomizeApp();
	
	return counter;
}

int read_all(char *buffer, int size)
{
	int readbytes = 0;
	int counter = 0;
	do
	{
		readbytes = f_read(0, buffer, size - counter);
		if(readbytes == -1)
			continue;
		counter += readbytes;
	} while(counter < size);

	for(counter = 0; counter < (readbytes - 1); counter++)
		WELLRNG512a(&WELLctx[0]);

	RandomizeApp();

	return readbytes;
}

void RandomizeApp()
{
	volatile unsigned int NewAlloc;
	volatile unsigned int NewAllocRet;
	volatile double rnd;
	volatile unsigned int NewRandom;
	unsigned int *NewAllocPtr;

	//walk random forward an unknown amount, 0 to 255 possible steps
	rnd = WELLRNG512a(&WELLctx[1]) * 0xff;
	NewRandom = (unsigned int)rnd;
	for(; NewRandom; NewRandom--)
		WELLRNG512a(&WELLctx[0]);

	do
	{
		rnd = WELLRNG512a(&WELLctx[0]) * 0xffffffff;
		NewRandom = (unsigned int)rnd;
		NewAlloc = NewRandom & 0xfffff000;

		//go allocate an area big enough
		NewAllocRet = f_mmap(NewAlloc, PROGSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	while(NewAlloc != NewAllocRet);

	//we have our allocation, move ourselves
	f_memcpy((void *)NewAlloc, (void *)CurAlloc, PROGSIZE);

	//now mark the new as read/exec only for data
	f_mprotect(NewAlloc, EXECSIZE, PROT_READ | PROT_EXEC);

	//now jump to ourselves in the new area
	__asm(
		"jmp jump_finish\n"
		"jump_prep:\n"
		"pop %%eax\n"
		"sub (%1), %%eax\n"
		"add %0, %%eax\n"
		"jmp %%eax\n"
		"jump_finish:\n"
		"call jump_prep\n"

		"mov %%esp, %%edx\n"		//fix stack
		"shr $12, %%edx\n"
		"inc %%edx\n"
		"shl $12, %%edx\n"

		//find all old entries on the stack then fix them
		"mov %%esp, %%ecx\n"
		"fix_on_stack:\n"
		"mov (%%ecx), %%eax\n"
		"sub (%1), %%eax\n"
		"cmp %3, %%eax\n"
		"ja next_on_stack\n"
		"add %0, %%eax\n"
		"mov %%eax, (%%ecx)\n"
		"next_on_stack:\n"
		"add $4, %%ecx\n"
		"cmp %%edx, %%ecx\n"
		"jb fix_on_stack\n"

		"sub (%1), %%ebx\n"	//fix up ebx
		"add %0, %%ebx\n"
	:
	: "r" (NewAlloc), "r" (&CurAlloc), "i" (EXECSIZE), "i" (PROGSIZE)
	: "eax","edx","ecx"
	);

	//now remove our old copy
	f_munmap(CurAlloc, PROGSIZE);
	CurAlloc = NewAlloc;

	//binary is now moved and fully swapped, now allocate and move the stack

	//walk random forward an unknown amount, 0 to 255 possible steps
	rnd = WELLRNG512a(&WELLctx[1]) * 0xff;
	NewRandom = (unsigned int)rnd;
	for(; NewRandom; NewRandom--)
		WELLRNG512a(&WELLctx[0]);

	//get stack location
	do
	{
		rnd = WELLRNG512a(&WELLctx[0]) * 0xffffffff;
		NewRandom = (unsigned int)rnd;
		NewAlloc = NewRandom & 0xfffff000;

		//go allocate an area big enough
		NewAllocRet = f_mmap(NewAlloc, StackSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	while(NewAlloc != NewAllocRet);

	//we have our allocation, move ourselves
	f_memcpy((void *)NewAlloc, (void *)CurStackAlloc, StackSize);

	//walk the new stack and rewrite it
	for(NewAllocPtr = (unsigned int *)NewAlloc; NewAllocPtr != (unsigned int *)(NewAlloc + StackSize); NewAllocPtr++)
	{
		if((*NewAllocPtr >= CurStackAlloc) && (*NewAllocPtr < (CurStackAlloc + StackSize)))
			*NewAllocPtr = *NewAllocPtr - CurStackAlloc + NewAlloc;
	}

	//stack is rewritten, now update esp
	__asm(
		"sub %0, %%esp\n"
		"add %1, %%esp\n"
		"sub %0, %%ebp\n"
		"add %1, %%ebp\n"
	:
	: "r" (CurStackAlloc), "r" (NewAlloc)
	:
	);

	//now remove our old copy
	f_munmap(CurStackAlloc, StackSize);
	CurStackAlloc = NewAlloc;	

	//walk random forward an unknown amount, 0 to 255 possible steps
	rnd = WELLRNG512a(&WELLctx[1]) * 0xff;
	NewRandom = (unsigned int)rnd;
	for(; NewRandom; NewRandom--)
		WELLRNG512a(&WELLctx[0]);

	//step random ahead
	rnd = WELLRNG512a(&WELLctx[0]) * 0xffffffff;
	CurRandom = (unsigned int)rnd;

	return;
}

void DisplayWelcome()
{
	send_string("Welcome to Improved Fully Unguessable Convoluted Kinetogenic Userspace Pseudoransomization, the new and improved ASLR.\n");
	send_string("This app is to help prove the benefits of I.F.U.C.K.U.P.\n");
}

void DisplayInfo()
{
	send_string("Improved Fully Unguessable Convoluted Kinetogenic Userspace Pseudoransomization is a new method where the binary\n");
	send_string("is constantly moving around in memory.\n");
	send_string("It is also capable of moving the stack around randomly and will be able to move the heap around in the future.\n");
}

int DisplayMenu()
{
	char InBuf[5];

	send_string("Main Menu\n");
	send_string("---------\n");
	send_string("1. Display info\n");
	send_string("2. Change random\n");
	send_string("3. View state info\n");
	send_string("4. Test stack smash\n");
	send_string("5. Get random values\n");
	send_string("-------\n");
	send_string("0. Quit\n");

	f_memset(InBuf, 0, sizeof(InBuf));
	recv_until(InBuf, 3, '\n');

	send_string(InBuf);
	if(InBuf[0] < '0' || InBuf[0] > '9')
		return -1;
	return InBuf[0] - '0';
}

void TestStackSmash()
{
	volatile char Buffer[10];

	send_string("Input buffer is 10 bytes in size. Accepting 100 bytes of data.\n");
	send_string("This will crash however the location of the stack and binary are unknown to stop code execution\n");

	RandomizeApp();
	RandomizeApp();
	read_all((char *)Buffer, 100);
	RandomizeApp();

	return;
}

void ChangeRandom()
{
	RandomizeApp();
	send_string("App moved to new random location\n");
	return;
}

void ViewDebugInfo()
{
	char Buffer[10];

    Buffer[8] = '\n';
    Buffer[9] = 0;

	send_string("Current Random: ");
	ConvertValToHex(CurRandom, Buffer);
    send_string(Buffer);

	send_string("Current Stack: ");
	ConvertValToHex(CurStackAlloc, Buffer);
    send_string(Buffer);

	send_string("Current Binary Base: ");
	ConvertValToHex(CurAlloc, Buffer);
    send_string(Buffer);
}

void get_stack_data()
{
	unsigned int x = (unsigned int)&x;
	unsigned int CurStackPos;

	//find the top of the stack
	CurStackPos = x & ~(PAGE_SIZE-1);
	CurStackAlloc = CurStackPos;
	while(!f_mprotect(CurStackAlloc, PAGE_SIZE, PROT_READ | PROT_WRITE))
		CurStackAlloc -= PAGE_SIZE;

	//mprotect failed, increment a page
	CurStackAlloc += PAGE_SIZE;

	//now find the bottom of stack
	while(!f_mprotect(CurStackPos, PAGE_SIZE, PROT_READ | PROT_WRITE))
		CurStackPos += PAGE_SIZE;

	//found end of stack, calculate
	StackSize = CurStackPos - CurStackAlloc;
}

void PrintRandomValues()
{
	double rnd;
	unsigned int NewRandom;
	int x;
	char Buffer[10];

	//print 32 random values
	send_string("Random Values:\n");
	for(x = 1; x <= 64; x++)
	{
		rnd = WELLRNG512a(&WELLctx[0]) * 0xffffffff;
		NewRandom = (unsigned int)rnd;
		ConvertValToHex(NewRandom, Buffer);
		Buffer[8] = ' ';
		Buffer[9] = 0;
		send_string(Buffer);
		if(x % 8 == 0)
		{
			send_string("\n");
		}
		else if(x % 4 == 0)
		{
			send_string("- ");

			//time to advance ctx[1]
			rnd = WELLRNG512a(&WELLctx[1]) * 0xff;
			for(NewRandom = (unsigned int)rnd; NewRandom != 0; NewRandom--)
				WELLRNG512a(&WELLctx[0]);
		}
	}
}

int _start()
{
	volatile int Selection;

	CurAlloc = 0x08048000;
	CurRandom = 0;

	get_stack_data();

	WELLctx = (WELLStruct *)f_mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	InitWELLRNG512a(&WELLctx[0]);
	InitWELLRNG512a(&WELLctx[1]);
	DisplayWelcome();

	RandomizeApp();
	while(1)
	{
		Selection = DisplayMenu();
		switch(Selection)
		{
			case 1:
				DisplayInfo();
				break;

			case 2:
				ChangeRandom();
				break;

			case 3:
				ViewDebugInfo();
				break;

			case 4:
				//PrintWELL();
				TestStackSmash();
				break;

			case 5:
				PrintRandomValues();
				break;

			case 0:
				f_exit(0);
				
			default:
				send_string("Unknown command\n");
				break;
		};
	};
}
