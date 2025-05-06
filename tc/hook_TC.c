#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// Встроенное определение bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)

// Карта для хранения target_ip
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);  // Ключ для карты (не используем, всегда один элемент)
    __type(value, __u32); // Значение - IP-адрес назначения
    __uint(max_entries, 1); // Один элемент
} target_ip_map SEC(".maps");

// Карта для хранения IP-адресов источников
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 128);
} source_ip_map SEC(".maps");

SEC("tc")
int tc_trap_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    __u32 dest_ip = ip->daddr;
    __u32 src_ip = ip->saddr;
    __u32 initial_value = 1;

    bpf_printk("Packet dest_ip: %x, source_ip: %x\n", dest_ip, src_ip);

    // Чтение target_ip из карты
    __u32 *target_ip_ptr = bpf_map_lookup_elem(&target_ip_map, &((__u32){0}));
    if (!target_ip_ptr) {
        bpf_printk("Target IP not set in target_ip_map\n");
        return TC_ACT_OK;
    }

    __u32 target_ip = *target_ip_ptr;
    bpf_printk("Packet dest_ip: %x, target_ip: %x\n", dest_ip, target_ip);

    if (dest_ip == target_ip) {
        bpf_printk("Match found for target IP. Source IP: %x\n", src_ip);

        __u32 *counter = bpf_map_lookup_elem(&source_ip_map, &src_ip);
        if (counter) {
            __sync_fetch_and_add(counter, 1);
            bpf_printk("Updated source IP count for %x\n", src_ip);
        } else {
            bpf_map_update_elem(&source_ip_map, &src_ip, &initial_value, BPF_ANY);
            bpf_printk("Added new source IP %x with initial count 1\n", src_ip);
        }
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
