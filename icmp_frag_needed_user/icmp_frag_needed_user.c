#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>

// Структуры для работы
struct iphdr *create_ip_header(struct iphdr *orig_ip, int mtu_limit);
struct icmphdr *create_icmp_header(struct iphdr *ip, struct icmphdr *icmp, int mtu_limit);

// Функция подсчёта контрольной суммы
unsigned short in_cksum(unsigned short *addr, int len);

// Обработка пакета
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Got packet with size %d\n", header->len);
    int mtu_limit = *(int *)args;
    struct ether_header *eth = (struct ether_header *)packet;

    // Проверка Ethernet
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    // Получаем IP заголовок
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    int ip_len = ntohs(ip->tot_len);

    // Проверяем DF и длину
    if ((ntohs(ip->frag_off) & IP_DF) && ip_len > mtu_limit) {
        printf("Packet too big (%d bytes), DF set → sending ICMP Fragmentation Needed\n", ip_len);

        // Создаём RAW сокет
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            perror("socket");
            return;
        }

        // Включаем возможность отправлять свой IP-заголовок
        int enable = 1;
        setsockopt(sockfd, SOL_IP, IP_HDRINCL, &enable, sizeof(enable));

        char sendbuf[1500];
        memset(sendbuf, 0, sizeof(sendbuf));

        // Создаём заголовки
        struct iphdr *reply_ip = create_ip_header(ip, mtu_limit);
        struct icmphdr *reply_icmp = (struct icmphdr *)(sendbuf + sizeof(struct iphdr));
        char *payload = (char *)reply_icmp + sizeof(struct icmphdr);

        // Заполняем ICMP
        reply_icmp->type = ICMP_DEST_UNREACH;
        reply_icmp->code = ICMP_FRAG_NEEDED;
        reply_icmp->un.frag.mtu = htons(mtu_limit); // Рекомендуемый MTU

        // Копируем часть оригинального IP-пакета
        memcpy(payload, ip, 64);

        // Вычисляем контрольные суммы
        reply_icmp->checksum = in_cksum((unsigned short *)reply_icmp, sizeof(struct icmphdr) + 64);
        reply_ip->check = in_cksum((unsigned short *)reply_ip, sizeof(struct iphdr));

        // Адрес назначения
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = ip->saddr;

        // Отправляем пакет
        if (sendto(sockfd, sendbuf, ntohs(reply_ip->tot_len), 0,
                  (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("sendto failed");
        } else {
            printf("Sent ICMP Destination Unreachable (mtu=%d)\n", mtu_limit);
        }

        close(sockfd);
    }
}

// Формирование IP заголовка
struct iphdr *create_ip_header(struct iphdr *orig_ip, int mtu_limit) {
    static char sendbuf[1500];
    struct iphdr *ip = (struct iphdr *)sendbuf;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = orig_ip->daddr; // Отправляем от Ubuntu
    ip->daddr = orig_ip->saddr; // Назначение — хост

    return ip;
}

// Формирование ICMP заголовка
struct icmphdr *create_icmp_header(struct iphdr *ip, struct icmphdr *icmp, int mtu_limit) {
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = ICMP_FRAG_NEEDED;
    icmp->un.frag.mtu = htons(mtu_limit); // Рекомендуемый MTU

    return icmp;
}

// Подсчёт контрольной суммы
unsigned short in_cksum(unsigned short *addr, int len) {
    register long sum = 0;
    unsigned short answer = 0;

    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1) {
        *(u_char *)(&answer) = *(u_char *)addr;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <mtu_limit>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *dev = argv[1];
    int mtu_limit = atoi(argv[2]);

    printf("MTU_LIMIT = %d. Listening on interface %s...\n", mtu_limit, dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    // Передаём mtu_limit через пользовательские данные
    pcap_loop(handle, 0, handle_packet, (u_char *)&mtu_limit);

    pcap_close(handle);
    return 0;
}
