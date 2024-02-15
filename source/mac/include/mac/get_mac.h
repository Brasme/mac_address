/*
Ref: https://stackoverflow.com/questions/16710040/arp-request-and-reply-using-c-socket-programming
*/

#ifndef MAC_GET_MAC_H_
#define MAC_GET_MAC_H_

#ifdef __cplusplus
extern "C" {
#endif

int get_MAC(const char *addr, const char *dport);

#ifdef __cplusplus
}
#endif

#endif