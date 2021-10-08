#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>

/*
 * Declare the BPF map in static memory. This will get loaded on startup.
 */
struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 3);
  __type(key, __u32);
  __type(value, __u32);
} test_map SEC(".maps");


/*
 * This updates the test map, which is an LRU cache where the key is the source address, and the value is 1.
 */
__always_inline void update_bpf_map(__be32 saddr)
{
    __u32 key = __be32_to_cpu(saddr); // Intentionally keeping this in network order since it's more readable this way.
    __u32 new_val = 1;

    bpf_map_update_elem(&test_map, &key, &new_val, 0);
}

/*
 * BPF Verifier: Any "direct packet" access needs to be checked so that memory accesses aren't out of bounds.
 */
__always_inline int check_access(struct __sk_buff *skb, void *starting_position, __u32 bytes_accessed)
{
    // This checks the pointer address (i.e. the bytes we're reading in), doesn't reach beyond the SKB.
    if( (starting_position + bytes_accessed) > (void*)skb->data_end)
    {
        bpf_printk(
            "SKB memory access check failed: start=0x%x, end=0x%x",
            (void*)starting_position,
            (void*)starting_position + bytes_accessed);

        bpf_printk(
            "SKB memory access check failed: skb_start=0x%x, skb_end=0x%x",
            (void*)skb->data,
            (void*)skb->data_end);

        return false;
    }

    return true;
}

__always_inline void print_eth(const struct ethhdr *eth)
{
    bpf_printk("------Ethernet------");
    // BPF functions have a 5 function argument limit due to the stack only having 5 stack registers.
    bpf_printk("-src_mac[0:2]=0x%x%x%x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
    bpf_printk("-src_mac[3:5]=0x%x%x%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("-dst_mac[0:2]=0x%x%x%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
    bpf_printk("-dst_mac[3:5]=0x%x%x%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("-proto=0x%x", __be16_to_cpu(eth->h_proto)); // Proto is in network order, need to convert to host order.
}

__always_inline void print_ipv4(const struct iphdr *ip)
{
    bpf_printk("------IPv4-------");
    bpf_printk("-ihl=0x%x", ip->ihl);
    bpf_printk("-version=0x%x", ip->version);
    bpf_printk("-tos=0x%x", ip->tos);
    bpf_printk("-tot_len=0x%x", ip->tot_len);
    bpf_printk("-id=0x%x", __be16_to_cpu(ip->ihl));
    bpf_printk("-frag_offset=0x%x", __be16_to_cpu(ip->frag_off));
    bpf_printk("-ttl=0x%x", ip->ttl);
    bpf_printk("-protocol=0x%x", ip->protocol);
    bpf_printk("-header csum=0x%x", ip->check);
    bpf_printk("-saddr=0x%x", ip->saddr);
    bpf_printk("-daddr=0x%x", ip->daddr);
}

__always_inline void print_arp(const struct arphdr *arp) {
    bpf_printk("------ARP_REQ-------");
	bpf_printk("-ar_hrd=0x%x", arp->ar_hrd);
	bpf_printk("-ar_pro=0x%x", arp->ar_pro);
	bpf_printk("-ar_hln=0x%x", arp->ar_hln);
	bpf_printk("-ar_pln=0x%x", arp->ar_pln);
	bpf_printk("-ar_op=0x%x", arp->ar_op);
}

__always_inline void print_udp(const struct udphdr *udp)
{
    bpf_printk("------UDP------");
    bpf_printk("-source=0x%x", udp->source);
	bpf_printk("-dest=0x%x", udp->dest);
	bpf_printk("-len=0x%x", udp->len);
	bpf_printk("-check=0x%x", udp->check);
}

__always_inline void print_tcp(const struct tcphdr *tcp)
{
    bpf_printk("------TCP------");
    bpf_printk("-source=0x%x", tcp->source);
	bpf_printk("-dest=0x%x", tcp->dest);
	bpf_printk("-seq=0x%x", tcp->seq);
	bpf_printk("-ack_seq=0x%x", tcp->ack_seq);
	bpf_printk("-window=0x%x", tcp->window);
	bpf_printk("-check=0x%x", tcp->check);
	bpf_printk("-urg_ptr=0x%x", tcp->urg_ptr);
}

/*
 * Example of how various fields of a packet in an SKB may be accessed.
 */
__always_inline void print_metadata(struct __sk_buff *skb)
{
    // L2
    struct ethhdr *eth = (void*)skb->data;
    if(!check_access(skb, eth, sizeof(struct ethhdr)))
    {
        return;
    }
    print_eth(eth);
    __u16 eth_proto = __be16_to_cpu(eth->h_proto);

    // L3
    void* next = (void*)eth + sizeof(struct ethhdr);
    __u16 ip_proto = 0;
    switch(eth_proto) {
        case ETH_P_ARP:
        {
            struct arphdr *arp = next;
            if(!check_access(skb, arp, sizeof(struct arphdr)))
            {
                return;
            }
            print_arp(arp);
            return;
        }

        case ETH_P_IP:
        {
            struct iphdr *ip = next;
            if(!check_access(skb, ip, sizeof(struct iphdr)))
            {
                return;
            }
            print_ipv4(ip);
            update_bpf_map(ip->saddr);

            next = ip + sizeof(struct iphdr);
            ip_proto = ip->protocol;
            break;
        }

        default:
        {
            bpf_printk("Unhandled eth proto: 0x%x", eth_proto);
            return;
        }
    }

    // L4
    switch(ip_proto) {
        case IPPROTO_UDP:
        {
            struct udphdr *udp = next;
            if(!check_access(skb, udp, sizeof(struct udphdr)))
            {
                return;
            }
            print_udp(udp);
            break;
        }

        case IPPROTO_TCP:
        {
            struct tcphdr *tcp = next;
            if(!check_access(skb, tcp, sizeof(struct tcphdr)))
            {
                return;
            }
            print_tcp(tcp);
            break;
        }

        default:
        {
            bpf_printk("Unhandled ip proto: 0x%x", ip_proto);
            break;
        }
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
    print_metadata(skb);
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";