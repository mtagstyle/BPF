# BPF
BPF Example

To run:
```
git submodule init
git submodule update

docker build . --tag bpf_example

docker run -itd \
-v /sys/kernel/debug:/sys/kernel/debug:rw \
--privileged \
--name bpf_example \
bpf_example bash

docker exec -it bpf_example bash
cd /tmp/example/scripts
./load_bpf_prog.sh
```