INCLUDE = -I/home/cfc4n/download/linux-5.11.0/tools/lib/

all: build

build:
	clang -g -Wall -Werror -O2 -emit-llvm $(INCLUDE) -c bpf-accounting.c -o - | llc -march=bpf -filetype=obj -o bpf-accounting.o
	go build
clean:
	rm -rf bpf-accounting.o
	rm -rf bpf-accounting