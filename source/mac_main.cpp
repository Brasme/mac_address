#include <stdio.h>

#include "arp_lib_test.h"

#include "mac/get_mac.h"
int test_mac_lib(const char *ip)
{
    get_MAC(ip,"12346");
}    

#include "arp_request_test.h"



int main(int argc, const char **argv) {
    int ret = -1;
    if (argc != 3) {
        printf("Usage: %s <INTERFACE> <DEST_IP>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *ip = argv[2];
    test_arp_lib(ifname, ip);

    char buffer0[1024];        
    { 
        const interface_t *list = query_adapters_ipv6(buffer0,1024);
        for (const interface_t *i = list; i->adapter ; ++i) {
            printf("Adapter(ipv6): %s => IP: %s\n",i->adapter,i->ip);
        }
    }

    const interface_t *list = query_adapters_ipv4(buffer0,1024);
    for (const interface_t *i = list; i->adapter ; ++i) {
        char buffer1[24];
        char buffer2[24];

        MacAddr mac=arp_request(ip,i);

        printf("Adapter(ipv4): %s => IP: %s, Mac=%s => arp(%s)=>Mac:%s\n",i->adapter,i->ip,MacAddr(*i->mac).toStr(buffer1,24),ip,mac.toStr(buffer2,24));
        
    }

    test_mac_lib(ip);

}
