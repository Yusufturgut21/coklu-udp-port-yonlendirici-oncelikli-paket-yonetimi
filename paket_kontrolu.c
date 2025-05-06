#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE 10 // Tampon boyutu
#define FRAME_SIZE 1500
#define PORT1 8100
#define PORT2 8200
#define PORT3 8300
#define PORT4 8400
#define PORT5 8500
#define max_packet 15

#define PACKETMANAGEMENTSUCCESS 0 // Başarı kodu
#define PACKETMANAGEMENTERROR 1   // Hata kodu

struct CircularBuffer
{
    char frames[BUFFER_SIZE][FRAME_SIZE + 2]; // Çerçeve verileri
    int head;                                 // Baş işaretçi
    int tail;                                 // Kuyruk işaretçi
    int count;                                // Mevcut çerçeve sayısı
};
int buffer1_packet_count = 0;
int buffer2_packet_count = 0;
int buffer3_packet_count = 0;
int buffer4_packet_count = 0;
int buffer5_packet_count = 0;

typedef struct
{
    uint8_t *data;
    uint16_t *byte_count;
} thread_data_t;

struct CircularBuffer buffer1;
struct CircularBuffer buffer2;
struct CircularBuffer buffer3;
struct CircularBuffer buffer4;
struct CircularBuffer buffer5;

uint32_t pull_data(struct CircularBuffer *buffer, uint8_t *data, uint16_t *byte_count);
uint32_t push_data(struct CircularBuffer *buffer, const uint8_t *data, uint16_t byte_count);

void tamponBasla(struct CircularBuffer *buffer)
{
    buffer->head = 0;
    buffer->tail = 0;
    buffer->count = 0;
}

uint32_t push_data(struct CircularBuffer *buffer, const uint8_t *data, uint16_t byte_count)
{
    if (buffer->count >= BUFFER_SIZE)
    {
        // Tampon dolu
        return PACKETMANAGEMENTERROR;
    }

    memcpy(buffer->frames[buffer->tail], &byte_count, sizeof(byte_count));
    memcpy(&buffer->frames[buffer->tail][2], data, byte_count);
    buffer->tail = (buffer->tail + 1) % BUFFER_SIZE;
    buffer->count++;

    return PACKETMANAGEMENTSUCCESS;
}

uint32_t pull_data(struct CircularBuffer *buffer, uint8_t *data, uint16_t *byte_count)
{
    if (buffer->count == 0)
    {
        // Tampon boş
        return PACKETMANAGEMENTERROR;
    }

    memcpy(byte_count, buffer->frames[buffer->head], sizeof(uint16_t));
    memcpy(data, &buffer->frames[buffer->head][2], *byte_count);

    buffer->head = (buffer->head + 1) % BUFFER_SIZE;
    buffer->count--;
    return PACKETMANAGEMENTSUCCESS;
}

void buffer_icerigi(struct CircularBuffer *buffer)
{
    int index = buffer->head;
    for (int i = 0; i < buffer->count; i++)
    {
        struct ether_header *eth_header = (struct ether_header *)buffer->frames[index];
        struct iphdr *iph = (struct iphdr *)(buffer->frames[index] + sizeof(struct ether_header));
        struct udphdr *udph = (struct udphdr *)(buffer->frames[index] + sizeof(struct ether_header) + sizeof(struct iphdr));
        printf("Buffer'daki çerçeve %d: Kaynak Port: %d, Hedef Port: %d\n", i + 1, ntohs(udph->source), ntohs(udph->dest));
        index = (index + 1) % BUFFER_SIZE;
    }
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *eth_header;
    struct iphdr *iph;
    struct udphdr *udph;

    eth_header = (struct ether_header *)packet;
    iph = (struct iphdr *)(packet + sizeof(struct ether_header));
    udph = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

    if (iph->protocol == IPPROTO_UDP)
    {
        int dest_port = ntohs(udph->dest);
        if (dest_port == PORT1)
        {
            printf("Çerçeve yakalandı, Port: %d\n", dest_port);
            push_data(&buffer1, packet, pkthdr->caplen);
        }
        if (dest_port == PORT2)
        {
            printf("Çerçeve yakalandı, Port: %d\n", dest_port);
            push_data(&buffer2, packet, pkthdr->caplen);
        }
        if (dest_port == PORT3)
        {
            printf("Çerçeve yakalandı, Port: %d\n", dest_port);
            push_data(&buffer3, packet, pkthdr->caplen);
        }
        if (dest_port == PORT4)
        {
            printf("Çerçeve yakalandı, Port: %d\n", dest_port);
            push_data(&buffer4, packet, pkthdr->caplen);
        }
        if (dest_port == PORT5)
        {
            printf("Çerçeve yakalandı, Port: %d\n", dest_port);
            push_data(&buffer5, packet, pkthdr->caplen);
        }
    }
}

uint32_t getPrioritizedPacket(uint8_t *data, uint16_t *byte_count)
{
    int buffer1_sent = 0;
    int buffer2_sent = 0;
    int buffer3_sent = 0;
    int buffer4_sent = 0;
    int buffer5_sent = 0;

    while (1)
    {
        usleep(200000); // 200 ms gecikme

        if (buffer1.count > 0 && buffer1_sent < 10)
        {
            buffer1_sent++;
            return pull_data(&buffer1, data, byte_count);
        }

        usleep(200000); // 200 ms gecikme

        if (buffer2.count > 0 && buffer2_sent < 20)
        {
            buffer2_sent++;
            return pull_data(&buffer2, data, byte_count);
        }

        usleep(200000); // 200 ms gecikme

        if (buffer3.count > 0 && buffer3_sent < 30)
        {
            buffer3_sent++;
            return pull_data(&buffer3, data, byte_count);
        }

        usleep(200000); // 200 ms gecikme

        if (buffer4.count > 0 && buffer4_sent < 15)
        {
            buffer4_sent++;
            return pull_data(&buffer4, data, byte_count);
        }

        usleep(200000); // 200 ms gecikme

        if (buffer5.count > 0 && buffer5_sent < 25)
        {
            buffer5_sent++;
            return pull_data(&buffer5, data, byte_count);
        }

        // Eğer belirli bir buffer'dan gönderilen paketler belirtilen sayıyı geçtiyse,
        // diğer buffer'lara geçilmek üzere döngüye geri dönülür.
        if (buffer1_sent >= 10 && buffer2_sent >= 20 && buffer3_sent >= 30 && buffer4_sent >= 15 && buffer5_sent >= 25)
        {
            buffer1_sent = 0;
            buffer2_sent = 0;
            buffer3_sent = 0;
            buffer4_sent = 0;
            buffer5_sent = 0;
        }

    }
}


void send_packet(const char *interface, uint8_t *data, uint16_t byte_count);

void *getPrioritizedPacket_thread(void *arg)
{
    uint8_t data[FRAME_SIZE + 2];
    uint16_t byte_count;

    while (1)
    {
        if (getPrioritizedPacket(data, &byte_count) == PACKETMANAGEMENTSUCCESS)
        {
            send_packet("enp0s3", data, byte_count);
        }

        usleep(10000); // 10 ms gecikme, işlemci yükünü azaltmak için
    }
    return NULL;
}

void send_packet(const char *interface, uint8_t *data, uint16_t byte_count)
{
    char dest_ip[INET6_ADDRSTRLEN] = "192.168.88.18";
    int sockfd;
    struct ifreq ifreq;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;

    strncpy(ifreq.ifr_name, interface, IFNAMSIZ - 1);

    struct ether_header *eh = (struct ether_header *)data;
    struct iphdr *iph = (struct iphdr *)(data + sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *)(data + sizeof(struct ether_header) + sizeof(struct iphdr));

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
    {
        perror("socket olusturma hatası");
        exit(1);
    }

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("INDEX ATAMA HATASI");
        exit(1);
    }

    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_hatype = ARPHRD_ETHER;
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, eh->ether_dhost, ETH_ALEN);

    if (ioctl(sockfd, SIOCGIFADDR, &ifreq) < 0)
    {
        perror("SIOCGIFADDR");
        exit(1);
    }

    iph->daddr = inet_addr(dest_ip);

    if (iph->protocol == IPPROTO_UDP)
    {
        if (ntohs(udph->dest) == PORT1)
        {
            udph->dest = htons(8101);
        }
        else if (ntohs(udph->dest) == PORT2)
        {
            udph->dest = htons(8201);
        }
        else if (ntohs(udph->dest) == PORT3)
        {
            udph->dest = htons(8301);
        }
        else if (ntohs(udph->dest) == PORT4)
        {
            udph->dest = htons(8401);
        }
        else if (ntohs(udph->dest) == PORT5)
        {
            udph->dest = htons(8501);
        }

        if (sendto(sockfd, data, byte_count, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        {
            perror("soket gönderilemedi...");
            close(sockfd);
            exit(1);
        }
        else
        {
            printf("paket başarıyla gönderildi %d portuna gönderilen paketin boyutu %hu\n", ntohs(udph->dest), byte_count);
        }
    }

    close(sockfd);
}

void *pcap_loop_thread(void *arg)
{
    pcap_t *handle = (pcap_t *)arg;
    pcap_loop(handle, -1, pcap_callback, NULL);
    return NULL;
}

int main()
{
    char *interface = "enp0s3";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    tamponBasla(&buffer1);
    tamponBasla(&buffer2);
    tamponBasla(&buffer3);
    tamponBasla(&buffer4);
    tamponBasla(&buffer5);

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Cihaz açılamadı %s: %s\n", interface, errbuf);
        return 2;
    }

    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, getPrioritizedPacket_thread, NULL);
    pthread_create(&thread2, NULL, pcap_loop_thread, (void *)handle);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    pcap_close(handle);

    return 0;
}