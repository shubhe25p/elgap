# elgap
ebpf+ldms+grafana

## Getting Started with EBPF locally (tested on MacOS Intel)

1. Install Virtual Box (https://www.virtualbox.org/wiki/Downloads) with Ubuntu 22.04
     - Github Codespace (Azure linux) doesn't work
     - Can work with Cloud Platforms but requires multiple cores
       
2. Ubuntu 22.04 ISO (https://releases.ubuntu.com/jammy/)
     - Azure linux doesn't work, got some strange linux header files error.
     - Ubuntu 23/24 also didn't work for some unkown reason.


### Learning eBPF

1. https://github.com/lizrice/learning-ebpf
2. https://github.com/iovisor/bcc/examples

Setting up eBPF:

```
sudo apt update
sudo apt install clang llvm libelf-dev
```

*BCC packages for both the Ubuntu Universe, and the iovisor builds are outdated. Currently, building from source is currently the only way to get up to date packaged version of bcc.*

```
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
```

```
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

### Compiling and Running the Programs
To compile and run these eBPF programs, you can use the following commands:
1. *Compile the eBPF Program:*
```
bash
   clang -O2 -target bpf -c program_name.c -o program_name.o
```
2. *Load and Attach the eBPF Program:*
```
bash
   bpftool prog load program_name.o /sys/fs/bpf/program_name
   bpftool prog attach /sys/fs/bpf/program_name tracepoint:[tracepoint] /sys/kernel/debug/tracing/instances/[instance_name]
```   
3. *Run the User-Space Program to Collect Events:*
```
c
   #include <bpf/libbpf.h>
   #include <stdio.h>
   #include <stdlib.h>
   #include <unistd.h>

   static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
       struct event_t *event = data;
       printf("PID: %d, Command: %s, Sysctl: %s\n", event->pid, event->comm, event->sysctl_name);
   }

   int main() {
       struct perf_buffer *pb = NULL;
       int map_fd;

       map_fd = bpf_obj_get("/sys/fs/bpf/program_name");
       pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);

       while (1) {
           perf_buffer__poll(pb, 100);
       }

       perf_buffer__free(pb);
       return 0;
   }
```

*.bpf files for actual BPF programs, .c files for user programs*