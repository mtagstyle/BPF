FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

# Dependencies
RUN apt-get update -y
RUN apt-get -y install clang
RUN apt-get -y install llvm
RUN apt-get -y install build-essential
RUN apt-get -y install libz-dev
RUN apt-get -y install libelf-dev
RUN apt-get -y install pkg-config
RUN apt-get -y install git
RUN apt-get -y install iproute2
RUN apt-get -y install iputils-ping
RUN apt-get -y install linux-headers-generic

# bpftool
WORKDIR /tmp
RUN git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
RUN cd linux/tools/bpf/bpftool/ && \
sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
printf 'feature-libbfd=0\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1\nfeature-zlib=1' >> FEATURES_DUMP.bpftool && \
FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
strip bpftool && \
ldd bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
	-e "not a dynamic executable" || \
	( echo "Error: bpftool is not statically linked"; false ) && \
mv bpftool /usr/bin && rm -rf /tmp/linux

COPY vendor /tmp/vendor
RUN make -C /tmp/vendor/libbpf/src install

RUN ls -al "/usr/src"

COPY example /tmp/example
RUN make -C /tmp/example
RUN ls /tmp/example

ENTRYPOINT ["/tmp/example/scripts/load_bpf_prog.sh"]