#!/bin/bash

BASEDIR=$(dirname "$0")
IFACE_NAME=bpf_veth

# Load the BPF program into the BPF subsystem (Under the hood, bpftool is making syscalls to bpf())
function load_bpf_program() {
    PROG_PINS=/sys/fs/bpf/netstat_demo
    [ -e ${PROG_PINS} ] && echo "Detected BPF program already loaded, removing." && rm -rf ${PROG_PINS}
    # Pins the specified BPF programs to the location of ${PROG_PINS}, loads as a classifer type BPF program.
    bpftool prog loadall ${BASEDIR}/../build/netstat.o ${PROG_PINS} type classifier || exit 1
}

function attach_bpf_program() {
    # Set up a Linux VETH pair to test the ingress and egress programs
    ip link del ${IFACE_NAME}_in || true
    ip link add ${IFACE_NAME}_in type veth peer name ${IFACE_NAME}_out
    ip link set ${IFACE_NAME}_in up
    ip link set ${IFACE_NAME}_out up
    tc qdisc replace dev ${IFACE_NAME}_out clsact # Tell traffic control to use the "classifier-action" filter

    # Attach the BPF program to a network hook
    tc filter del dev ${IFACE_NAME}_out ingress # Remove any existing bpf programs
    tc filter del dev ${IFACE_NAME}_out egress # Remove any existing bpf programs
    tc filter add dev ${IFACE_NAME}_out ingress bpf object-pinned ${PROG_PINS}/ingress_prog direct-action
    tc filter add dev ${IFACE_NAME}_out egress bpf object-pinned ${PROG_PINS}/egress_prog direct-action
}

# Follows /sys/kernel/debug/tracing/trace_pipe for any output from the BPF programs
function listen_output() {
    python3 ${BASEDIR}/inject_random_udp.py &
    PID=$!
    cat /sys/kernel/debug/tracing/trace_pipe
}

function ctrl_c() {
    echo "Cleaning up"
    kill ${PID}
}

trap ctrl_c INT

echo "Loading BPF program..."
load_bpf_program
echo "Success."

echo "Attaching BPF program to TC subsystem..."
attach_bpf_program
echo "Success."

echo "Listening for output..."
listen_output
echo "Exiting."