#include <linux/bpf.h>
#include <linux/pkt_cls.h>

SEC("ingress")
int ingress(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

SEC("egress")
int egress(struct __sk_buff *skb)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";