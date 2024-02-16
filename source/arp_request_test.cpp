#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> 
#include <net/if.h>

#include "arp_request_test.h"
StringArray::StringArray(char *mem,size_t size): mem_(mem), head_((char**)mem), tail_(mem+size), size_(size)
{
    if (remain()>=0) {
        *head_=nullptr;
    }
}

bool StringArray::append(const char *str,size_t size) {
    if (size==0)
        size=strlen(str);
    size_t n=size+1;
    if (remain()<(n+sizeof(char*)))
        return false;
    tail_-=n;
    memcpy(tail_,str,size);
    tail_[size]='\0';
    *head_=tail_;
    head_++;
    *head_=nullptr;
    return true;
}

const char **StringArray::list() const { return (const char**)mem_; }
size_t StringArray::remain() const { return (size_t)(tail_-(char*)head_)-sizeof(char*); }


#include <stdio.h>    //printf
#include <string.h>   //strncpy
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close

// Return null terminated list of local IP address (strings) from adapter
const struct interface_t *query_adapters_ipv4(char *mem,size_t size) 
{
    StringArray s(mem,size);    
    struct ifaddrs *ifAddr, *ifa;
    char name[NI_MAXHOST];

    if (getifaddrs(&ifAddr) == -1) {
        perror("getifaddrs");
        return (const interface_t*)s.list();
    }

    // Walk through linked list, maintaining head pointer so we can free list later
    for (ifa = ifAddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, "lo") == 0 || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        int rc=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in), name, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (rc==0) {
            
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct ifreq ifr;
            memset(&ifr,0,sizeof(ifreq));
            ifr.ifr_addr.sa_family = AF_INET;
            strncpy(ifr.ifr_name , ifa->ifa_name , IFNAMSIZ-1);
            ioctl(fd, SIOCGIFHWADDR, &ifr);
            close(fd);
    
            // printf("* Interface(ipv4): %s\t Address: %s\n", ifa->ifa_name, name);
            s.append(ifa->ifa_name);         
            s.append(name);   
            s.append(ifr.ifr_hwaddr.sa_data,6); // mac addr
        } else {
            printf("* getnameinfo() failed for ipv4 at %s: %s\n", gai_strerror(rc),ifa->ifa_name);                
        }
    }

    freeifaddrs(ifAddr);
    return (const interface_t*)s.list();
}

// Return null terminated list of local IP address (strings) from adapter
const struct interface_t *query_adapters_ipv6(char *mem,size_t size) 
{
    StringArray s(mem,size);    
    struct ifaddrs *ifAddr, *ifa;
    char name[NI_MAXHOST];

    if (getifaddrs(&ifAddr) == -1) {
        perror("getifaddrs");
        return (const interface_t*)s.list();
    }

    for (ifa = ifAddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, "lo") == 0 || ifa->ifa_addr->sa_family != AF_INET6) 
            continue;

        int rc=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in6), name, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (rc==0)        
        {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct ifreq ifr;
            memset(&ifr,0,sizeof(ifreq));
            ifr.ifr_addr.sa_family = AF_INET;
            strncpy(ifr.ifr_name , ifa->ifa_name , IFNAMSIZ-1);
            int rc=ioctl(fd, SIOCGIFHWADDR, &ifr);
            if (rc!=0) {
                printf("ioctl() => %i\n",rc);
            }
            close(fd);
            
            s.append(ifa->ifa_name); //adapter
            s.append(name); // ip
            s.append(ifr.ifr_hwaddr.sa_data,6);
        
        } else {
            printf("* getnameinfo() failed for ipv6 at %s: %s\n", gai_strerror(rc),ifa->ifa_name);                
        }
    }

    freeifaddrs(ifAddr);
    return (const interface_t*)s.list();
}

MacAddr::MacAddr() {
    memset(m,0,6);
}

MacAddr::MacAddr(const mac_addr_t& other) {
    memcpy(m,other.m,6);
}

const char *MacAddr::toStr(char *buffer,size_t size) const
{
    char *b=buffer;
    if (size<21) {        
        for (size_t i=0;i<size;++i)
            b[i]='-';
        if (size>0)
            b[size-1]='\0';
        return b;
    }

    const char *hexChar="0123456789abcdef";    
    for (int i=0;i<6;++i) {
        const unsigned int v=m[i]&0xff;
        if (i!=0)
            *b++=':';
        *b++=hexChar[(v&0xf0)>>4];
        *b++=hexChar[v&0x0f];        
    }
    *b++='\0';
    return buffer;
}


#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#define debug(x...) printf(x);printf("\n");
#define info(x...) printf(x);printf("\n");
#define warn(x...) printf(x);printf("\n");
#define err(x...) printf(x);printf("\n");

struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};


struct mac_addr_t arp_request(const char *dest_ip_str,const struct interface_t *interface)
{
    MacAddr mac;

    struct in_addr dest_ip;
    if (!inet_aton(dest_ip_str, &dest_ip)) {
        perror("Invalid destination IP address");
        return mac;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation error");
        return mac;
    }

    // ARP request packet
    struct ether_arp eth_arp_req_msg;
    memset(&eth_arp_req_msg, 0, sizeof(struct ether_arp));
    eth_arp_req_msg.arp_hrd = htons(ARPHRD_ETHER);
    eth_arp_req_msg.arp_pro = htons(ETH_P_IP);
    eth_arp_req_msg.arp_hln = 6;
    eth_arp_req_msg.arp_pln = 4;
    eth_arp_req_msg.arp_op = htons(ARPOP_REQUEST);
    
    // Set source MAC address
    // You need to replace these values with your source MAC address
    memcpy(eth_arp_req_msg.arp_sha, interface->mac->m, 6);
    
    // Set source IP address
    // You need to replace this value with your source IP address
    struct in_addr src_ip;
    inet_aton(interface->ip, &src_ip);
    memcpy(eth_arp_req_msg.arp_spa, &src_ip, 4);

    // Set destination IP address
    memcpy(eth_arp_req_msg.arp_tpa, &dest_ip, 4);

    // Set destination MAC address as broadcast
    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth_arp_req_msg.arp_tha, dest_mac, 6);

    // Construct Ethernet frame
    sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(sockaddr_ll));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_ARP);
    dest_addr.sll_ifindex = if_nametoindex(interface->adapter);
    dest_addr.sll_halen = 6;
    memcpy(dest_addr.sll_addr, dest_mac, 6);

    struct ether_header eth_header;
    memset(&eth_header, 0, sizeof(struct ether_header));
    memcpy(eth_header.ether_dhost, dest_mac, 6);
    memcpy(eth_header.ether_shost, interface->mac->m, 6);
    eth_header.ether_type = htons(ETH_P_ARP);

    // Send ARP request
    sendto(sockfd, &eth_header, sizeof(struct ether_header), 0, 
           (struct sockaddr*)&dest_addr, sizeof(struct sockaddr_ll));
    sendto(sockfd, &eth_arp_req_msg, sizeof(struct ether_arp), 0, 
           (struct sockaddr*)&dest_addr, sizeof(struct sockaddr_ll));

    // read arp response
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
    if (length == -1) {
        perror("recvfrom()");
        return mac;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet");
        return mac;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        debug("Not an ARP reply");
        return mac;
    }
    debug("received ARP len=%ld", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));
    debug("Sender IP: %s", inet_ntoa(sender_a));

    debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);

    memcpy(mac.m,arp_resp->sender_mac,6);

    close(sockfd);
    return mac;
}