#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>

/*
 * Example of how various fields of a packet in an SKB may be accessed.
 */
__always_inline void print_metadata(struct __sk_buff *skb) {

    // Ethernet
    struct ethhdr *eth = (struct ethhdr*)&skb->data;
    void* memes = (void*)((void*)eth + sizeof(struct ethhdr));
    bpf_printk("Beginning of eth header is: %x, End of eth header is: %x, data end is: %x",eth,  memes, (void*)skb->data_end);
    if((void*)(eth + sizeof(struct ethhdr)) < (void*)skb->data_end) {
        bpf_printk("- Interface Idx: %d", skb->ifindex);
        bpf_printk("- Src MAC: %pM", eth->h_source);
        // bpf_printk("- Dest MAC: %pM", __be16_to_cpu(eth->h_proto));
    }

    // IP = SKB start + Eth Size
    struct iphdr *ip = (struct iphdr*)(&skb->data + sizeof(struct ethhdr));
    if ((void*)(ip + sizeof(struct iphdr)) < (void*)skb->data_end) {
        __u32 saddr = ip->saddr;
        bpf_printk("- Source IP: %d", saddr);
        bpf_printk("- Dest IP: %x", ip->daddr);
    }
}

SEC("ingress_prog")
int ingress(struct __sk_buff *skb)
{
    bpf_printk("Got a packet from ingress!");
    print_metadata(skb);
    return TC_ACT_OK;
}

SEC("egress_prog")
int egress(struct __sk_buff *skb)
{
    bpf_printk("Got a packet from egress!");
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";