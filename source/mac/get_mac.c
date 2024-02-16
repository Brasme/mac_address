#include "mac/get_mac.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <fcntl.h>

/* 
    https://www.linuxquestions.org/questions/programming-9/getting-mac-address-from-ethernet-packet-in-c-434241/
*/

#define info(x...) { printf(x);printf("\n"); }

int get_MAC(const char *addr, const char *dport)
{
    int sock, sockfd, n;
    char buffer[2048];
    unsigned char *iphead, *ethhead;
    struct hostent *he;
    struct sockaddr_in remote_addr;
    struct sockaddr_in local_addr;
                                   // struct ifreq iface;
                                   // struct sockaddr_in *addr;
    struct ether_addr ether;

    info("* socket(SOCK_RAW,ETH_P_IP)");
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    { 
        perror("socket");
        return -1;
    }

    info("* gethostbyname(%s)",addr);
    if ((he = gethostbyname(addr)) == NULL)
    { // get the host info
        perror("gethostbyname");
        return -1;
    }
    
    info("* socket(SOCK_STREAM)");    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

    // info("* fcntl()"); 
    // if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < -1) 
    // {
    //     perror("fcntl");    
    // }

    bzero((char * ) &remote_addr, sizeof(struct sockaddr_in)); 
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(atoi(dport));
    remote_addr.sin_addr = *((struct in_addr *)he->h_addr_list[0]);
    
    bzero((char * ) &local_addr, sizeof(struct sockaddr_in)); 
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(0);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    info("* bind()"); 
    if (bind(sockfd, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_in)) < 0)
    {
        perror("bind");
    }

    info("* connect(0x%08x:%i)",ntohl(remote_addr.sin_addr.s_addr),atoi(dport));        
    if (connect(sockfd, (struct sockaddr *)&remote_addr,
                sizeof(struct sockaddr)) == -1)
    {
        perror("connect");
        return -1;
    }
    while (1)
    {
        info("* recvfrom()");
        if (n = recvfrom(sock, buffer, 2048, 0, NULL, NULL) == -1)
        {
            perror("recvfrom");
            close(sock);
            return -1;
        }

        // n = recv(sock,buffer,2048,0);
        ethhead = buffer;
        if (ethhead != NULL)
        {

            printf("Source MAC address: "
                   "%02x:%02x:%02x:%02x:%02x:%02x\n",
                   ethhead[0], ethhead[1], ethhead[2],
                   ethhead[3], ethhead[4], ethhead[5]);
            printf("Destination MAC address: "
                   "%02x:%02x:%02x:%02x:%02x:%02x\n",
                   ethhead[6], ethhead[7], ethhead[8],
                   ethhead[9], ethhead[10], ethhead[11]);
        }
        iphead = buffer + 14; /* Skip Ethernet header */
        if (*iphead == 0x45)
        { /* Double check for IPv4
           * and no options present */
            printf("Source host %d.%d.%d.%d\n",
                   iphead[12], iphead[13],
                   iphead[14], iphead[15]);
            printf("Dest host %d.%d.%d.%d\n",
                   iphead[16], iphead[17],
                   iphead[18], iphead[19]);
            printf("Source,Dest ports %d,%d\n",
                   (iphead[20] << 8) + iphead[21],
                   (iphead[22] << 8) + iphead[23]);
            printf("Layer-4 protocol %d\n", iphead[9]);
        }
    }
    return 0;
}
