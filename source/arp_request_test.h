#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
struct StringArray {
    StringArray(char *mem,size_t size);
    bool append(const char *str,size_t size=0);    
    const char **list() const;

    private:
        size_t remain() const;
        char *mem_;
        char **head_;
        char *tail_;
        size_t size_;
};

extern "C"
{
#endif

struct mac_addr_t {
    unsigned char m[6];
};

struct interface_t {
    char       *adapter;
    char       *ip;
    mac_addr_t *mac;    
};

// Return null terminated list of local IP address (strings) from adapter
const struct interface_t* query_adapters_ipv4(char *mem,size_t size);
const struct interface_t* query_adapters_ipv6(char *mem,size_t size);

struct mac_addr_t arp_request(const char *dest_ip_str,const struct interface_t *interface);

#ifdef __cplusplus
struct MacAddr : mac_addr_t {
    MacAddr();
    MacAddr(const mac_addr_t &other);
    const char *toStr(char *buffer,size_t size) const;
};

}
#endif