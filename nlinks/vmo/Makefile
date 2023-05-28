
SRC := vm.cpp \
	   cpu.cpp \
	   parser.cpp
HEADERS := vm.hpp \
		   cpu.hpp \
		   parser.hpp

all: vm vm_debug objs

objs: parser.o vm.o cpu.o

vm: ${SRC} ${HEADERS}
	g++ -O2 ${SRC} -DSTANDALONE -o vm

vm_debug: ${SRC} ${HEADERS}
	g++ -O0 -g -DSTANDALONE -DDEBUG ${SRC} -o vm_debug

parser.o: parser.cpp parser.hpp
	g++ -O2 parser.cpp -c -o parser.o

vm.o: vm.cpp vm.hpp
	g++ -O2 vm.cpp -c -o vm.o

cpu.o: cpu.cpp cpu.hpp
	g++ -O2 cpu.cpp -c -o cpu.o

clean:
	rm -f vm vm_debug vm.o cpu.o parser.o
