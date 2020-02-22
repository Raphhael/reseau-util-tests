#ifndef H_ARP
#define H_ARP

/**
 * Manipulation des trames ARP
 * 
 * struct ether_arp {
 *         struct arphdr {
 *                 unsigned short int ar_hrd;		 Format of hardware address.  
 *                 unsigned short int ar_pro;		 Format of protocol address.  
 *                 unsigned char      ar_hln;		 Length of hardware address.  
 *                 unsigned char      ar_pln;               Length of protocol address.  
 *                 unsigned short int ar_op;		 ARP opcode (command).
 *         } ea_hdr;		         fixed-size header 
 *         uint8_t arp_sha[ETH_ALEN];	 sender hardware address 
 *         uint8_t arp_spa[4];		 sender protocol address 
 *         uint8_t arp_tha[ETH_ALEN];	 target hardware address 
 *         uint8_t arp_tpa[4];		 target protocol address 
 * };
 *
 *
 */

#include <netinet/in.h>

/************************************************************
 ******* Manipulation des adresses mac de l'entête ARP ******
 ***********************************************************/
 
/**
 * @var mac     Adresse mac sender au format hexadécimal deux-pointé
 * @var buffer  En-tête ARP
 */
void    arp_set_sender_amac(const char *mac, void *buffer);

/**
 * @var mac     Adresse mac target au format hexadécimal deux-pointé
 * @var buffer  En-tête ARP
 */
void    arp_set_target_amac(const char *mac, void *buffer);

/**
 * @var mac     Adresse mac sender au format <struct ether_addr>
 * @var buffer  En-tête ARP
 */
void    arp_set_sender_nmac(struct ether_addr *mac, void *buffer);
/**
 * @var mac     Adresse mac target au format <struct ether_addr>
 * @var buffer  En-tête ARP
 */
void    arp_set_target_nmac(struct ether_addr *mac, void *buffer);

/**
 * Met à 0 l'adresse mac source dans l'en-tête ARP
 * @var buffer  En-tête ARP
 */
void    arp_reset_sender_mac(void *buffer);
/**
 * Met à 0 l'adresse mac target dans l'en-tête ARP
 * @var buffer  En-tête ARP
 */
void    arp_reset_target_mac(void *buffer);



/************************************************************
 ******* Manipulation des adresses IP de l'entête ARP *******
 ***********************************************************/


/**
 * @var ip      Adresse IP sender au format décimal pointé
 * @var buffer  En-tête ARP
 */
void    arp_set_sender_aip(const char *ip, void *buffer);
/**
 * @var ip      Adresse IP target au format décimal pointé
 * @var buffer  En-tête ARP
 */
void    arp_set_target_aip(const char *ip, void *buffer);

/**
 * @var ip      Adresse IP sender au format in_addr_t (uint32_t)
 * @var buffer  En-tête ARP
 */
void    arp_set_sender_nip(in_addr_t ip, void *buffer);

/**
 * @var ip      Adresse IP target au format in_addr_t (uint32_t)
 * @var buffer  En-tête ARP
 */
void    arp_set_target_nip(in_addr_t ip, void *buffer);


/**
 * Met à 0 l'adresse IP sender dans l'en-tête ARP
 * @var buffer  En-tête ARP
 */
void    arp_reset_sender_ip(void *buffer);

/**
 * Met à 0 l'adresse IP target dans l'en-tête ARP
 * @var buffer  En-tête ARP
 */
void    arp_reset_target_ip(void *buffer);

/**
 * Initialise l'en-tête ARP
 */
void    arp_init(uint16_t arptype, void *buffer);


void    arp_set_isat(void *buffer);
void    arp_set_whois(void *buffer);

/** 
 * Créé une en-tête ARP
 * @var mac_sender     Adresse mac pour future réponse
 * @var mac_target     Adresse mac de destination
 * @var ip_sender      Adresse IP réponse
 * @var ip_target      Adresse IP cible
 * @var arptype        Type de requete ARP
 * @var buffer         Buffer de taille sup. ou égale à sizeof(struct ether_arp)
 */
void    arp_create(const char *mac_sender, const char *ip_sender,
                     const char *mac_target, const char *ip_target,
                     uint16_t arptype, void *buffer);
#endif
