/**
 * Outils pour création et modification de trame ethernet
 *
 * Structures utilisées :
 *
 *
 * struct sockaddr_ll {
 *      unsigned short sll_family;    Toujours AF_PACKET
 *      unsigned short sll_protocol;  Protocole niveau physique
 *      int            sll_ifindex;   Numéro d'interface
 *      unsigned short sll_hatype;    Type d'entête
 *      unsigned char  sll_pkttype;   Type de paquet
 *      unsigned char  sll_halen;     Longueur de l'adresse
 *      unsigned char  sll_addr[8];   Adresse niveau physique
 * };
 *
 * struct ether_header
 * {
 *      uint8_t  ether_dhost[ETH_ALEN];	destination eth addr
 *      uint8_t  ether_shost[ETH_ALEN];	source ether addr
 *      uint16_t ether_type;	        packet type ID field
 * }
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ether.h> /* ether_xxx func */
#include <linux/if_packet.h> /* struct struct sockaddr_ll */
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <net/if.h>


#include "../header/util.h"


void    maccpy(const char *hex, void *buffer) {
	struct ether_addr *mac = ether_aton(hex);
	__C(mac, NULL, "mac_converter: hex pas valide ");
	memcpy(buffer, mac, sizeof(struct ether_addr));
}



void    ethernet_set_asrc(const char *mac, void *buffer) {
        maccpy(mac, ((struct ether_header *) buffer)->ether_shost);
}
void    ethernet_set_adst(const char *mac, void *buffer) {
        maccpy(mac, ((struct ether_header *) buffer)->ether_dhost);
}



void    ethernet_set_nsrc(struct ether_addr *mac, void *buffer) {
        memcpy(((struct ether_header *) buffer)->ether_shost, mac, sizeof(struct ether_addr));
}
void    ethernet_set_ndst(struct ether_addr *mac, void *buffer) {
        memcpy(((struct ether_header *) buffer)->ether_dhost, mac, sizeof(struct ether_addr));
}




void    ethernet_init(uint16_t ethertype, void *buffer) {
        struct ether_header *trame = (struct ether_header *) buffer;
        memset(buffer, 0, sizeof(struct ether_header));
        trame->ether_type = htons(ethertype);
}


void    ethernet_sockaddr_init(struct sockaddr_ll *addr, const char *ifname) {
        memset(addr, 0, sizeof(struct sockaddr_ll));
        
        addr->sll_family = AF_PACKET;
	addr->sll_ifindex = if_nametoindex(ifname);
	__C(addr->sll_ifindex, 0, "ethernet_sockaddr_init: nom de l'interface incorrect ");
	addr->sll_halen = ETH_ALEN;
}


void    ethernet_create(const char *src, const char *dst, uint16_t ethertype, void *buffer) {
        ethernet_init(ethertype, buffer);
        ethernet_set_asrc(src, buffer);
        ethernet_set_adst(dst, buffer);
}

void    ethernet_send(int sockfd, void *buffer, size_t len, struct sockaddr_ll *addr) {
        struct ether_header *ethdr = (struct ether_header *)buffer;
	struct sockaddr_ll tmpaddr;
	
	memcpy(&tmpaddr, addr, sizeof(struct sockaddr_ll));
        memcpy(tmpaddr.sll_addr, ethdr->ether_shost, sizeof(struct ether_addr));

	__C(sendto(sockfd, buffer, len, 0, (struct sockaddr *)&tmpaddr,
	                sizeof(struct sockaddr_ll)), -1, "send_ethernet_frame: sendto fail ");
}


