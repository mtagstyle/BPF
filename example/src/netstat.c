#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

SEC("ingress_prog")
int ingress(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

SEC("egress_prog")
int egress(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";