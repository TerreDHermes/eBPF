#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <stdint.h>          // Для uint32_t
#include <arpa/inet.h>       // Для htons, ntohl
#include <netinet/in.h>      // Для IPPROTO_ICMP
#include <bpf/bpf_helpers.h> // Для bpf_trace_printk

#define ETH_P_IP 0x0800
#define IP_DF 0x4000
#define MTU_LIMIT 900

// Определим структуру ключа карты (IP-адрес и порт)
struct packet_data_key {
    __be32 dst_ip; // Адрес назначения
    __u32 length;  // Длина пакета
};

// Карта для хранения данных для формирования ICMP-ответа
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct packet_data_key); // Ключ: адрес назначения и длина
    __type(value, __u32);               // Значение: отметка существования
    __uint(max_entries, 1024);          // Количество записей
} packet_data_map SEC(".maps");

SEC("xdp")
int xdp_icmp_monitor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet заголовок
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        bpf_printk("Ethernet header overflow!\n");
        return XDP_PASS;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        bpf_printk("Non-IPv4 packet skipped.\n");
        return XDP_PASS;
    }

    // IP заголовок
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        bpf_printk("IP header overflow!\n");
        return XDP_PASS;
    }

    int ip_len = ntohs(ip->tot_len);

    // Проверяем DF и размер
    if ((ntohs(ip->frag_off) & IP_DF) && ip_len > MTU_LIMIT) {
        bpf_printk("DF flag detected with oversized packet (%d bytes).\n", ip_len);

        // Готовим ключ карты
        struct packet_data_key key = {};
        key.dst_ip = ip->saddr; // Адрес назначения
        key.length = (__u32)ip_len; // Длина пакета

        // Записываем в карту признак присутствия
        __u32 value = 1;
        bpf_map_update_elem(&packet_data_map, &key, &value, BPF_NOEXIST);

        return XDP_DROP; // Блокируем дальнейшую передачу пакета
    }

    bpf_printk("Passing through normal packet processing.\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";