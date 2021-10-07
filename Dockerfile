FROM ubuntu:20.04

RUN apt-get update -y
RUN apt-get -y install clang
RUN apt-get -y install llvm
RUN apt-get -y install build-essential
RUN apt-get -y install libz-dev
RUN apt-get -y install libelf-dev
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y install pkg-config
#RUN apt-get -y install linux-headers-$(uname -r)
COPY example /tmp
RUN make -C /tmp/vendor/libbpf/src install
RUN make -C /tmp
RUN ls /tmp