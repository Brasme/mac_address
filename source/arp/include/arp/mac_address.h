/*
Ref: https://stackoverflow.com/questions/16710040/arp-request-and-reply-using-c-socket-programming
*/

#ifndef MAC_ADDRESS_H_
#define MAC_ADDRESS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip);
    
/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip);

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex);

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd);


/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd);


#ifdef __cplusplus
}
#endif

#endif