#include "arp_lib_test.h"

#include "arp/arp_mac.h"

#include <arpa/inet.h> // inet_addr()
#include <stdio.h>
#include <unistd.h>

#define MAC_LENGTH 6

#define debug(x...) { printf(x);printf("\n"); }
#define info(x...) { printf(x);printf("\n"); }
#define warn(x...) { printf(x);printf("\n"); }
#define err(x...) { printf(x);printf("\n"); }


/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arp_lib(const char *ifname, const char *ip) {
    int ret = -1;
    uint32_t dst = inet_addr(ip);
    if (dst == 0 || dst == 0xffffffff) {
        printf("Invalid source IP\n");
        return 1;
    }

    uint32_t src;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(ifname, &src, mac, &ifindex)) {
        err("get_if_info failed, interface %s not found or no IP set?", ifname);
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        err("Failed to bind_arp()");
        goto out;
    }

    if (send_arp(arp_fd, ifindex, (const unsigned char*)mac, src, dst)) {
        err("Failed to send_arp");
        goto out;
    }

    while(1) {
        int r = read_arp(arp_fd);
        if (r == 0) {
            info("Got reply, break out");
            break;
        }
    }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}
