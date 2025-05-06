#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <stdint.h>          // Для uint32_t
#include <arpa/inet.h>       // Для htons, ntohl
#include <netinet/in.h>      // Для IPPROTO_ICMP
#include <bpf/bpf_helpers.h> // Для bpf_trace_printk

SEC("xdp_icmp_logger")
int xdp_icmp_logger_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Проверка Ethernet-заголовка
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Проверка IPv4
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Получение IP-заголовка
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Проверка ICMP
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    // Получение ICMP-заголовка
    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // Логирование всех ICMP-пакетов
    uint32_t src_ip = ntohl(ip->saddr);

    // Формируем сообщение: IP-адрес в десятичном формате
    char fmt[] = "ICMP Packet: SRC=%u, Type=%d, Code=%d\n";
    bpf_trace_printk(fmt, sizeof(fmt), src_ip, icmp->type, icmp->code);

    return XDP_PASS; // Пропускаем пакет дальше
}

char _license[] SEC("license") = "GPL";