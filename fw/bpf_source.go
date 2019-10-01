package main

const Source string = `
#include <uapi/linux/bpf.h>
#include <linux/ip.h>

int filter(struct xdp_md *meta) {
	void *data_end = (void*)(long)meta->data_end;
	void *data = (void*)(long)meta->data;

	struct ethhdr *eth = data;

	uint16_t h_proto;
	uint64_t nh_off = 0;
	int index = 0;

	nh_off = sizeof(*eth);

	if (data + nh_off > data_end) {
		return XDP_DROP;
	}

	h_proto = eth->h_proto;
	
	// While the following code appears to be duplicated accidentally,
	// it's intentional to handle double tags in ethernet frames.
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;
	
		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end) {
			return XDP_DROP;
		}
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;
	
		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end) {
			return XDP_DROP;
		}
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
}
`
