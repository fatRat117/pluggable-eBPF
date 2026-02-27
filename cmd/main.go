package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type ExecveData struct {
	Pid       uint32
	Uid       uint32
	Timestamp uint64
	Comm      [16]byte
	Filename  [256]byte
}

var (
	execveSpec *ebpf.CollectionSpec
	execveProg *ebpf.Program
	execveMap  *ebpf.Map
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("ebpf/execve.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}
	defer coll.Close()

	execveProg = coll.Programs["trace_execve"]
	if execveProg == nil {
		log.Fatal("Failed to find trace_execve program")
	}

	execveMap = coll.Maps["execve_events"]
	if execveMap == nil {
		log.Fatal("Failed to find execve_events map")
	}

	rd, err := perf.NewReader(execveMap, os.Getpagesize()*64)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Tracing execve syscalls... Press Ctrl+C to exit.")

	go func() {
		<-sigCh
		fmt.Println("\nExiting...")
		os.Exit(0)
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == perf.ErrClosed {
				return
			}
			log.Printf("Error reading perf event: %v", err)
			continue
		}

		if len(record.RawSample) < 32 {
			continue
		}

		var data ExecveData
		copy((*(*[512]byte)(unsafe.Pointer(&data)))[:], record.RawSample)

		comm := cStringToGo(data.Comm[:])
		filename := cStringToGo(data.Filename[:])

		fmt.Printf("[%d] pid=%d uid=%d comm=%s filename=%s\n",
			data.Timestamp/1e9, data.Pid, data.Uid, comm, filename)
	}
}

func cStringToGo(b []byte) string {
	n := 0
	for _, c := range b {
		if c == 0 {
			break
		}
		n++
	}
	return string(b[:n])
}
