package main

const Source string = `
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <uapi/linux/tcp.h>

// struct ipNet {
// 	__be32 ip;
// 	__be32 mask;
// }

BPF_HASH4(ipv4, __be32, unsigned char, 100000);
// BPF_HASH4(addrs, __be32, long long int, 100000);
// BPF_HASH4(ipAddrs, __be32, bool, 100000);
BPF_HASH4(sPorts, __be16, bool, 65600);

BPF_PERF_OUTPUT(trace);

static inline bool addrMatched(struct iphdr *iph, int byteNum) {
	__be32 saddr = iph->saddr;
	// unsigned char *c = (unsigned char*) &saddr;
	unsigned char *c = &saddr;
	c = c + byteNum;
	unsigned char t = *c ^ 0b00000001;
	*c = *c & t;
	unsigned char* cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b00000010;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b00000100;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b00001000;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b00010000;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b00100000;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b01000000;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	t = *c ^ 0b10000000;
	*c = *c & t;
	cc = ipv4.lookup(&saddr);
	if (cc) {
		return true;
	}
	return false;
}

static bool isFiltered(struct iphdr *iph) {
	unsigned char *c = ipv4.lookup(&iph->saddr);
	if (c) {
		return true;
	}
	if (addrMatched(iph, 3)) {
		return true;
	}
	if (addrMatched(iph, 2)) {
		return true;
	}
	if (addrMatched(iph, 1)) {
		return true;
	}
	if (addrMatched(iph, 0)) {
		return true;
	}
	return false;
}



int filter(struct xdp_md *meta) {
	void* data_end = (void*)(long)meta->data_end;
    void* data = (void*)(long)meta->data;

    struct ethhdr *eth = data;

    // drop packets
   // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    int index;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    // While the following code appears to be duplicated accidentally,
    // it's intentional to handle double tags in ethernet frames.
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_DROP;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_DROP;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }


	if (h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;
		if ((void*)&iph[1] > data_end) {
			return XDP_DROP;
		}
		// if (isFiltered(iph)) {
		// 	 return XDP_DROP;
		// }
		unsigned char *c = ipv4.lookup(&iph->saddr);
		if (c) {
			return XDP_DROP;
		} 
		// ///////Did something here with ip headers///////////
		// nh_off += sizeof(*iph);
		// struct tcphdr *tcph = data + nh_off;
		// if ((void*)&tcph[1] > data_end) {
		// 	return XDP_DROP;
		// }
		// char *p = sPorts.lookup(&tcph->source);
		// if (p) {
		// 	return XDP_DROP;
		// }
		//return XDP_DROP;
	}
	return XDP_PASS;
}
`
