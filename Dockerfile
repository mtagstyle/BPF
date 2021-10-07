FROM ubuntu:21.04

RUN apt-get update -y
RUN apt-get -y install clang llvm
RUN apt-get -y install build-essential
RUN apt-get -y install linux-headers-$(uname -r)
COPY example /tmp
RUN make -C /tmp
RUN ls /tmp