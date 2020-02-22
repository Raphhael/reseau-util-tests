#ifndef H_ETHERNET
#define H_ETHERNET
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
 *      uint16_t ether_type;		        packet type ID field
 * }
 *
 */
#include <net/ethernet.h>
#include <netinet/in.h>

/**
 * @var hex     "aa:bb:cc:dd:ee:ff"
 * @var buffer  buffer de taille sup. ou égale à sizeof(struct ether_addr) (6 octets)
 */
void    maccpy(const char *hex, void *buffer);

/**
 * @var mac     Adresse mac format "aa:bb:cc:dd:ee:ff"
 * @var buffer  buffer de taille sup. ou égale à sizeof(struct ether_addr) (6 octets)
 */
void    ethernet_set_asrc(const char *mac, void *buffer);
void    ethernet_set_adst(const char *mac, void *buffer);


/**
 * @var mac     Adresse mac au format <struct ether_addr>
 * @var buffer  buffer de taille sup. ou égale à sizeof(struct ether_addr) (6 octets)
 */
void    ethernet_set_nsrc(struct ether_addr *mac, void *buffer);
void    ethernet_set_ndst(struct ether_addr *mac, void *buffer);


/**
 * Initialise et remet à 0 une en-tête ethernet
 * @var ethertype Protocole de layer 3 OSI défini dans net/ethernet.h (ETHERTYPE_IP)
 * @var buffer    Buffer de taille sup. ou égale à sizeof(struct ether_header) (14 octets)
 */
void    ethernet_init(uint16_t ethertype, void *buffer);

/**
 * Initialise la sockaddr pour un socket
 * 
 */
void    ethernet_sockaddr_init(struct sockaddr_ll *addr, const char *ifname);


/**
 * Créer une frame ethernet
 * @var src       Adresse mac source en hexa :té
 * @var dst       Adresse mac destination en hexa :té
 * @var ethertype Protocole de layer 3 OSI défini dans net/ethernet.h (ETHERTYPE_IP)
 * @var buffer    Buffer de taille sup. ou égale à sizeof(struct ether_header) (14 octets)
 */
void    ethernet_create(const char *src, const char *dst, uint16_t ethertype, void *buffer);



/**
 * Envoyer une trame ethernet sur le réseau
 * @var sockfd  Socket d'envoi
 * @var buffer  Buffer de la trame
 * @var len     Longueur à envoyer
 * @var ifindex Interface par laquelle envoyer
 */
void    ethernet_send(int sockfd, void *buffer, size_t len, struct sockaddr_ll *addr);


#endif

