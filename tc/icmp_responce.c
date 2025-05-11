#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define IP_DF 0x4000
#define ICMP_DEST_UNREACH 3
#define ICMP_FRAG_NEEDED 4

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 version_ihl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        __be32 unused;
        struct {
            __be16 mtu;
        } un;
    } u;
};

SEC("classifier")
int icmp_reply_gen(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    int ip_len = ntohs(ip->tot_len);

    // Проверяем: установлен ли DF и превышает ли размер MTU=900
    if (ntohs(ip->frag_off) & IP_DF && ip_len > 900) {
        // Начинаем формировать ICMP-ответ
        struct {
            struct ethhdr eth;
            struct iphdr ip;
            struct icmphdr icmp;
            char payload[64]; // Часть оригинального заголовка для диагностики
        } __attribute__((packed)) pkt = {};

        // Ethernet
        memcpy(pkt.eth.h_dest, eth->h_source, 6);
        memcpy(pkt.eth.h_source, eth->h_dest, 6);
        pkt.eth.h_proto = eth->h_proto;

        // IP
        pkt.ip.version_ihl = 0x45; // IPv4, IHL = 5
        pkt.ip.tos = 0;
        pkt.ip.tot_len = htons(sizeof(pkt.ip) + sizeof(pkt.icmp) + sizeof(pkt.payload));
        pkt.ip.id = 0;
        pkt.ip.frag_off = 0;
        pkt.ip.ttl = 64;
        pkt.ip.protocol = IPPROTO_ICMP;
        pkt.ip.saddr = ip->daddr;
        pkt.ip.daddr = ip->saddr;

        // ICMP
        pkt.icmp.type = ICMP_DEST_UNREACH;
        pkt.icmp.code = ICMP_FRAG_NEEDED;
        pkt.icmp.u.un.mtu = htons(900); // Рекомендуемый MTU

        // Копируем часть оригинального заголовка для диагностики
        size_t copy_len = data_end - data;
        if (copy_len > sizeof(pkt.payload))
            copy_len = sizeof(pkt.payload);
        memcpy(pkt.payload, ip, copy_len);

        // Вычисляем контрольные суммы
        pkt.ip.check = 0;
        pkt.ip.check = bpf_csum_diff(0, 0, &pkt.ip, sizeof(pkt.ip), 0);
        pkt.icmp.checksum = 0;
        pkt.icmp.checksum = bpf_csum_diff(0, 0, &pkt.icmp, sizeof(pkt.icmp) + copy_len, 0);

        // Отправляем пакет
        return bpf_redirect_map(&tx_port, 0, BPF_F_BROADCAST);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";