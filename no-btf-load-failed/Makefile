.PHONY: all
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

all : generate build
    		

# $BPF_CLANG is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate .


build:
	CGO_ENABLED=0 go build .


clean:
	rm -f *.o
	rm -f no-btf-load-failed
	rm -f bpf_bpfeb.go
	rm -f bpf_bpfel.go
