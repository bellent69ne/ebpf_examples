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

BPF_HASH4(subnets, __be32, ipNet, 100000);
BPF_HASH4(ipAddrs, __be32, bool, 100000);
BPF_HASH4(sPorts, __be16, bool, 65600);


unsigned char turnOffLeastSignificant(unsigned char b) {
	bb = b;
	if bb%2 == 1 {
		return b - 1;
	}
	bb /= 2;
	if b%2 == 1 {
		return b - 2;
	}
	bb /= 2;
	if b%2 == 1 {
		return b - 4;
	}
	bb /= 2;
	if b%2 == 1 {
		return b - 8;
	}
	bb /= 2;
	if bb%2 == 1 {
		return b - 16;
	}
	bb /= 2;
	if bb%2 == 1 {
		return b - 32;
	}
	bb /= 2;
	if bb%2 == 1 {
		return b - 64;
	}
	bb /= 2;
	if bb%2 == 1 {
		return b - 128;
	}
}

bool isBlacklisted(__be32 *saddr) {
	bool *p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	// unsigned char *b = (unsigned char*) saddr;
	// b += 3;
	// bb = turnOffLeastSignificant(*b);
	// *b = bb;
	turnOffLSFromAddr(saddr, 3);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 3);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 3);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 3);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 2);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 2);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 2);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 2);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 1);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 1);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 1);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	turnOffLSFromAddr(saddr, 1);
	p = subnets.lookup(saddr);
	if (p) {
		return true;
	}
	return false;
}

void turnOffLSFromAddr(__be32 *saddr, int offset) {
	unsigned char *b = (unsigned char*) saddr;
	b += offset;
	bb = turnOffLeastSignificant(*b);
	*b = bb;
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


	// if (h_proto == htons(ETH_P_IP)) {
	// 	// struct iphdr *iph = data + nh_off;
	// 	// if ((void*)&iph[1] > data_end) {
	// 	// 	return XDP_DROP;
	// 	// }
	// 	// //char *a = ipAddrs.lookup(&iph->saddr);
	// 	// //if (a) {
	// 	// //	return XDP_DROP;
	// 	// //}
	// 	// if (iph->saddr != 33) {
	// 	// 	return XDP_DROP;
	// 	// }
	// 	// ///////Did something here with ip headers///////////
	// 	// nh_off += sizeof(*iph);
	// 	// struct tcphdr *tcph = data + nh_off;
	// 	// if ((void*)&tcph[1] > data_end) {
	// 	// 	return XDP_DROP;
	// 	// }
	// 	// char *p = sPorts.lookup(&tcph->source);
	// 	// if (p) {
	// 	// 	return XDP_DROP;
	// 	// }
	// 	return XDP_DROP;
	// }
	return XDP_DROP;
}
`
