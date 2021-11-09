//go:build linux
// +build linux

package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	TARGET_CGROUP_V2_PATH = "/sys/fs/cgroup/unified/cnxct"
	EBPF_PROG_ELF         = "./bpf-accounting.o"
)

type BpfCgroupStorageKey struct {
	CgroupInodeId uint64
	AttachType    ebpf.AttachType
	_             uint32	//内存对齐
}
type PerCPUCounters []uint64

type BPFCgroupNetworkDirection struct {
	Name       string
	AttachType ebpf.AttachType
}

var BPFCgroupNetworkDirections = []BPFCgroupNetworkDirection{
	{
		Name:       "ingress",
		AttachType: ebpf.AttachCGroupInetIngress,
	},
	{
		Name:       "egress",
		AttachType: ebpf.AttachCGroupInetEgress,
	},
}

func main() {
	log.Printf("Attaching eBPF monitoring programs to cgroup %s\n", TARGET_CGROUP_V2_PATH)

	// ------------------------------------------------------------
	// -- The real program initialization will be somewhere here --
	// ------------------------------------------------------------

	// Increase max locked memory (for eBPF maps)
	// For a real program, make sure to adjust to actual needs
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
	//low-overhead-cgroup-network-accounting-with-ebpf

	collec, err := ebpf.LoadCollection(EBPF_PROG_ELF)
	if err != nil {
		log.Fatal(err)
	}

	// Get a handle on the statistics map
	cgroup_counters_map := collec.Maps["cgroup_counters_map"]

	// Get cgroup folder inode number to use as a key in the per-cgroup map
	cgroupFileinfo, err := os.Stat(TARGET_CGROUP_V2_PATH)
	if err != nil {
		log.Fatal(err)
	}
	cgroupStat, ok := cgroupFileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		log.Fatal("Not a syscall.Stat_t")
	}
	cgroupInodeId := cgroupStat.Ino


	// Attach program to monitored cgroup
	for _, direction := range BPFCgroupNetworkDirections {
		link, err := link.AttachCgroup(link.CgroupOptions{
			Path:    TARGET_CGROUP_V2_PATH,
			Attach:  direction.AttachType,
			Program: collec.Programs[direction.Name],
		})
		if err != nil {
			log.Fatal(err)
		}
		defer link.Close()
	}

	// Wait until signaled
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT)
	signal.Notify(c, syscall.SIGTERM)

	// Periodically check counters
	ticker := time.NewTicker(5 * time.Second)

out:
	for {
		select {
		case <-ticker.C:
			log.Println("-------------------------------------------------------------")

			// ------------------------------------------
			// -- And here will be the counters report --
			// ------------------------------------------
			for _, direction := range BPFCgroupNetworkDirections {
				var perCPUCounters PerCPUCounters

				mapKey := BpfCgroupStorageKey{
					CgroupInodeId: cgroupInodeId,
					AttachType:    direction.AttachType,
				}

				if err := cgroup_counters_map.Lookup(mapKey, &perCPUCounters); err != nil {
					log.Printf("%s: error reading map (%v)", direction.Name, err)
				} else {
					log.Printf("%s: %d\n", direction.Name, sumPerCpuCounters(perCPUCounters))
				}
			}
		case <-c:
			log.Println("Exiting...")
			break out
		}
	}
}

func sumPerCpuCounters(perCpuCounters PerCPUCounters) uint64 {
	sum := uint64(0)
	for _, counter := range perCpuCounters {
		sum += counter
	}
	return sum
}