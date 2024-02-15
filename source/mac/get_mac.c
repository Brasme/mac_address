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
#include <netdb.h>

/* 
    https://www.linuxquestions.org/questions/programming-9/getting-mac-address-from-ethernet-packet-in-c-434241/
*/

int get_MAC(const char *addr, const char *dport)
{
    int sock, sockfd, n;
    char buffer[2048];
    unsigned char *iphead, *ethhead;
    struct hostent *he;
    struct sockaddr_in their_addr; // connector's address information
                                   // struct ifreq iface;
                                   // struct sockaddr_in *addr;
    struct ether_addr ether;

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
    { 
        perror("socket");
        return -1;
    }

    if ((he = gethostbyname(addr)) == NULL)
    { // get the host info
        perror("gethostbyname");
        return -1;
    }
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

    their_addr.sin_family = AF_INET;          // host byte order
    their_addr.sin_port = htons(atoi(dport)); // short, network byte order
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(&(their_addr.sin_zero), '\0', 8); // zero the rest of the struct

    if (connect(sockfd, (struct sockaddr *)&their_addr,
                sizeof(struct sockaddr)) == -1)
    {
        perror("connect");
        return -1;
    }
    while (1)
    {
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
