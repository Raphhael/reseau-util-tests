#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../header/util.h"
#include "../header/ethernet.h"

void    arp_set_sender_amac(const char *mac, void *buffer) {
        maccpy(mac, ((struct ether_arp *) buffer)->arp_sha);
}
void    arp_set_target_amac(const char *mac, void *buffer) {
        maccpy(mac, ((struct ether_arp *) buffer)->arp_tha);
}

void    arp_set_sender_nmac(struct ether_addr *mac, void *buffer) {
        memcpy(((struct ether_arp *) buffer)->arp_tha, mac, sizeof(struct ether_addr));
}
void    arp_set_target_nmac(struct ether_addr *mac, void *buffer) {
        memcpy(((struct ether_arp *) buffer)->arp_tha, mac, sizeof(struct ether_addr));
}

void    arp_reset_sender_mac(void *buffer) {
        memset(((struct ether_arp *) buffer)->arp_sha, 0, sizeof(struct ether_addr));
}
void    arp_reset_target_mac(void *buffer) {
        memset(((struct ether_arp *) buffer)->arp_tha, 0, sizeof(struct ether_addr));
}



/************************************************************
 ******* Manipulation des adresses IP de l'entête ARP *******
 ***********************************************************/



void    arp_set_sender_nip(in_addr_t ip, void *buffer) {
        memcpy(((struct ether_arp *) buffer)->arp_spa, &ip, sizeof(struct in_addr));
}
void    arp_set_target_nip(in_addr_t ip, void *buffer) {
        memcpy(((struct ether_arp *) buffer)->arp_tpa, &ip, sizeof(struct in_addr));
}

void    arp_set_sender_aip(const char *ip, void *buffer) {
        arp_set_sender_nip(inet_addr(ip), buffer);
}
void    arp_set_target_aip(const char *ip, void *buffer) {
        arp_set_target_nip(inet_addr(ip), buffer);
}

void    arp_reset_sender_ip(void *buffer) {
        memset(((struct ether_arp *) buffer)->arp_spa, 0, sizeof(struct in_addr));
}
void    arp_reset_target_ip(void *buffer) {
        memset(((struct ether_arp *) buffer)->arp_tpa, 0, sizeof(struct in_addr));
}

void    arp_set_whois(void *buffer) {
        ((struct ether_arp *) buffer)->ea_hdr.ar_op = htons(ARPOP_REQUEST);
}
void    arp_set_isat(void *buffer) {
        ((struct ether_arp *) buffer)->ea_hdr.ar_op = htons(ARPOP_REPLY);
}


void    arp_init(uint16_t arptype, void *buffer)
{
        struct	ether_arp  *arp = (struct ether_arp *) buffer;
        memset(arp, 0, sizeof(struct ether_arp));
        
        arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
        arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
        arp->ea_hdr.ar_op  = htons(arptype);
        arp->ea_hdr.ar_hln = (unsigned char) sizeof(struct ether_addr);
        arp->ea_hdr.ar_pln = (unsigned char) sizeof(struct in_addr);
}

void    arp_create(const char *mac_sender, const char *ip_sender,
                     const char *mac_target, const char *ip_target,
                     uint16_t arptype, void *buffer) {
        arp_init(arptype, buffer);
        arp_set_sender_aip(ip_sender, buffer);
        arp_set_target_aip(ip_target, buffer);
        arp_set_sender_amac(mac_sender, buffer);
        arp_set_target_amac(mac_target, buffer);
}



