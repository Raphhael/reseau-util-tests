#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>


#include "../header/util.h"

void    hex_dump(void *buf, size_t len) {
        uint32_t * b = buf;
        char     * c;
        int j;
        
        for(unsigned int i = 0; i < len / 4; i++, b++) {
                if(!(i % DUMP_NB_COL)) {
                        printf("\n0x%.4x\t|\t", i * DUMP_NB_COL);
                        c = (char *) b;
                        for(j = 1; c < (char *)buf + len && j <= DUMP_NB_COL * 4; j++, c++) {
                                if(*c <= 126 && *c >= 32)//(*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z'))
                                        printf("%c", *c);
                                else printf(".");
                                if(!(j % DUMP_NB_COL))
                                        ;//printf(" ");
                        }
                        for(;j <= DUMP_NB_COL * 4;j++) printf(" ");
                        printf("\t|  ");
                }
                printf("%.8X ", htonl(*b));
        }
        printf("\n");
}

void    fill_blank(const char *str, int size_total) {
        int spaces = size_total - strlen(str);
        for(; spaces >= 0; spaces--)
                printf(" ");
        printf(" ");
}


uint16_t calcul_checksum_16(void * obj, size_t len) {
        uint16_t *buf = obj       ; 
        uint16_t sum; 
        
        for ( sum = 0; len > 1; len -= 2, *buf++)
                sum = (*buf + sum) % 0xFFFF; //SI > FFFF, on prend le reste
        
        return ~sum; //CA1
}


void    reverse_dns_lookup(struct in_addr *addr) {
        struct hostent *host = NULL;
        host = gethostbyaddr(addr, sizeof(struct in_addr), AF_INET);
        if(!host) {
                switch(h_errno) {
                        case HOST_NOT_FOUND: printf(" HOST_NOT_FOUND "); break;
                        case NO_DATA: printf(" NO_DATA "); break;
                        case NO_RECOVERY: printf(" NO_RECOVERY "); break;
                        case TRY_AGAIN: printf(" TRY_AGAIN "); break;
                        default: fill_blank("", 40);
                }
        }
        else {
                printf("%s", host->h_name);
                fill_blank(host->h_name, 40);
        }
}

void    dns_lookup(const char *domain, struct sockaddr_in *target) {
        struct hostent *host = NULL;
        memset((struct sockaddr_in *) target, 0, sizeof(struct sockaddr_in));
        
        host = gethostbyname(domain);
        __C(host, NULL, "Impossible de trouver l'adresse IP ...");
        
        target->sin_port = htons(20);
        target->sin_family = host->h_addrtype;
        memcpy(&target->sin_addr, host->h_addr, sizeof(struct in_addr));
        
        printf("--- %s (%s) ---\n", domain, inet_ntoa(target->sin_addr));
}



int     socket_open_raw_packet(const char *ifname, struct ifreq *ifr, int proto) {
        int pktfd;
        struct sockaddr_ll addr;
        struct packet_mreq req;

        
        memset(ifr, 0, sizeof(struct ifreq));
        memset(&req, 0, sizeof(struct packet_mreq));
        
        strncpy(ifr->ifr_name, ifname, IFNAMSIZ);
        
	
	/* Ouverture socket */
        pktfd = socket(AF_PACKET, SOCK_RAW, htons(proto));
        __C(pktfd, -1, "socket_open_raw_packet: echec create socket ");
        
        /* Récupérer l'index de l'interface */
        __C( ioctl(pktfd, SIOCGIFINDEX, ifr, sizeof(struct ifreq)), 
                                        -1, "socket_open_raw_packet: interface introuvable ");
        
        /* On se met en promiscous */
        req.mr_ifindex = ifr->ifr_ifindex;
        req.mr_type = PACKET_MR_PROMISC;
        __C( setsockopt(pktfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *) &req, sizeof(struct packet_mreq)), 
                                        -1, "socket_open_raw_packet: echec set opt PACKET_MR_PROMISC ");
        
        
        /* Écouter uniquement cette interface */
	addr.sll_ifindex = ifr->ifr_ifindex;
        addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(proto);
        __C( setsockopt(pktfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)ifr, sizeof(struct ifreq)), 
                                        -1, "socket_open_raw_packet: setsockopt SO_BINDTODEVICE echec ");
        __C( bind(pktfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_ll)),
                                        -1, "socket_open_raw_packet: bind err ");
        
        
        
        return pktfd;
}

int     str_to_proto(char *str) {
        if(!strcmp(str, "ALL")) { return ETH_P_ALL; } 
        else if(!strcmp(str, "LOOP")) { return ETH_P_LOOP; } 
        else if(!strcmp(str, "PUP")) { return ETH_P_PUP; } 
        else if(!strcmp(str, "PUPAT")) { return ETH_P_PUPAT; } 
        else if(!strcmp(str, "TSN")) { return ETH_P_TSN; } 
        else if(!strcmp(str, "ERSPAN2")) { return ETH_P_ERSPAN2; } 
        else if(!strcmp(str, "IP")) { return ETH_P_IP; } 
        else if(!strcmp(str, "X25")) { return ETH_P_X25; } 
        else if(!strcmp(str, "ARP")) { return ETH_P_ARP; } 
        else if(!strcmp(str, "BPQ")) { return ETH_P_BPQ; } 
        else if(!strcmp(str, "IEEEPUP")) { return ETH_P_IEEEPUP; } 
        else if(!strcmp(str, "IEEEPUPAT")) { return ETH_P_IEEEPUPAT; } 
        else if(!strcmp(str, "BATMAN")) { return ETH_P_BATMAN; } 
        else if(!strcmp(str, "DEC")) { return ETH_P_DEC; } 
        else if(!strcmp(str, "DNA_DL")) { return ETH_P_DNA_DL; } 
        else if(!strcmp(str, "DNA_RC")) { return ETH_P_DNA_RC; } 
        else if(!strcmp(str, "DNA_RT")) { return ETH_P_DNA_RT; } 
        else if(!strcmp(str, "LAT")) { return ETH_P_LAT; } 
        else if(!strcmp(str, "DIAG")) { return ETH_P_DIAG; } 
        else if(!strcmp(str, "CUST")) { return ETH_P_CUST; } 
        else if(!strcmp(str, "SCA")) { return ETH_P_SCA; } 
        else if(!strcmp(str, "TEB")) { return ETH_P_TEB; } 
        else if(!strcmp(str, "RARP")) { return ETH_P_RARP; } 
        else if(!strcmp(str, "ATALK")) { return ETH_P_ATALK; } 
        else if(!strcmp(str, "AARP")) { return ETH_P_AARP; } 
        else if(!strcmp(str, "8021Q")) { return ETH_P_8021Q; } 
        else if(!strcmp(str, "ERSPAN")) { return ETH_P_ERSPAN; } 
        else if(!strcmp(str, "IPX")) { return ETH_P_IPX; } 
        else if(!strcmp(str, "IPV6")) { return ETH_P_IPV6; } 
        else if(!strcmp(str, "PAUSE")) { return ETH_P_PAUSE; } 
        else if(!strcmp(str, "SLOW")) { return ETH_P_SLOW; } 
        else if(!strcmp(str, "WCCP")) { return ETH_P_WCCP; } 
        else if(!strcmp(str, "MPLS_UC")) { return ETH_P_MPLS_UC; } 
        else if(!strcmp(str, "MPLS_MC")) { return ETH_P_MPLS_MC; } 
        else if(!strcmp(str, "ATMMPOA")) { return ETH_P_ATMMPOA; } 
        else if(!strcmp(str, "PPP_DISC")) { return ETH_P_PPP_DISC; } 
        else if(!strcmp(str, "PPP_SES")) { return ETH_P_PPP_SES; } 
        else if(!strcmp(str, "LINK_CTL")) { return ETH_P_LINK_CTL; } 
        else if(!strcmp(str, "ATMFATE")) { return ETH_P_ATMFATE; } 
        else if(!strcmp(str, "PAE")) { return ETH_P_PAE; } 
        else if(!strcmp(str, "AOE")) { return ETH_P_AOE; } 
        else if(!strcmp(str, "8021AD")) { return ETH_P_8021AD; } 
        else if(!strcmp(str, "802_EX1")) { return ETH_P_802_EX1; } 
        else if(!strcmp(str, "PREAUTH")) { return ETH_P_PREAUTH; } 
        else if(!strcmp(str, "TIPC")) { return ETH_P_TIPC; } 
        else if(!strcmp(str, "LLDP")) { return ETH_P_LLDP; } 
        else if(!strcmp(str, "MACSEC")) { return ETH_P_MACSEC; } 
        else if(!strcmp(str, "8021AH")) { return ETH_P_8021AH; } 
        else if(!strcmp(str, "MVRP")) { return ETH_P_MVRP; } 
        else if(!strcmp(str, "1588")) { return ETH_P_1588; } 
        else if(!strcmp(str, "NCSI")) { return ETH_P_NCSI; } 
        else if(!strcmp(str, "PRP")) { return ETH_P_PRP; } 
        else if(!strcmp(str, "FCOE")) { return ETH_P_FCOE; } 
        else if(!strcmp(str, "IBOE")) { return ETH_P_IBOE; } 
        else if(!strcmp(str, "TDLS")) { return ETH_P_TDLS; } 
        else if(!strcmp(str, "FIP")) { return ETH_P_FIP; } 
        else if(!strcmp(str, "80221")) { return ETH_P_80221; } 
        else if(!strcmp(str, "HSR")) { return ETH_P_HSR; } 
        else if(!strcmp(str, "NSH")) { return ETH_P_NSH; } 
        else if(!strcmp(str, "LOOPBACK")) { return ETH_P_LOOPBACK; } 
        else if(!strcmp(str, "QINQ1")) { return ETH_P_QINQ1; } 
        else if(!strcmp(str, "QINQ2")) { return ETH_P_QINQ2; } 
        else if(!strcmp(str, "QINQ3")) { return ETH_P_QINQ3; } 
        else if(!strcmp(str, "EDSA")) { return ETH_P_EDSA; } 
        else if(!strcmp(str, "DSA_8021Q")) { return ETH_P_DSA_8021Q; } 
        else if(!strcmp(str, "IFE")) { return ETH_P_IFE; } 
        else if(!strcmp(str, "AF_IUCV")) { return ETH_P_AF_IUCV; } 
        else if(!strcmp(str, "802_3_MIN")) { return ETH_P_802_3_MIN; } 
        else if(!strcmp(str, "802_3")) { return ETH_P_802_3; } 
        else if(!strcmp(str, "AX25")) { return ETH_P_AX25; } 
        else if(!strcmp(str, "ALL")) { return ETH_P_ALL; } 
        else if(!strcmp(str, "802_2")) { return ETH_P_802_2; } 
        else if(!strcmp(str, "SNAP")) { return ETH_P_SNAP; } 
        else if(!strcmp(str, "DDCMP")) { return ETH_P_DDCMP; } 
        else if(!strcmp(str, "WAN_PPP")) { return ETH_P_WAN_PPP; } 
        else if(!strcmp(str, "PPP_MP")) { return ETH_P_PPP_MP; } 
        else if(!strcmp(str, "LOCALTALK")) { return ETH_P_LOCALTALK; } 
        else if(!strcmp(str, "CAN")) { return ETH_P_CAN; } 
        else if(!strcmp(str, "CANFD")) { return ETH_P_CANFD; } 
        else if(!strcmp(str, "PPPTALK")) { return ETH_P_PPPTALK; } 
        else if(!strcmp(str, "TR_802_2")) { return ETH_P_TR_802_2; } 
        else if(!strcmp(str, "MOBITEX")) { return ETH_P_MOBITEX; } 
        else if(!strcmp(str, "CONTROL")) { return ETH_P_CONTROL; } 
        else if(!strcmp(str, "IRDA")) { return ETH_P_IRDA; } 
        else if(!strcmp(str, "ECONET")) { return ETH_P_ECONET; } 
        else if(!strcmp(str, "HDLC")) { return ETH_P_HDLC; } 
        else if(!strcmp(str, "ARCNET")) { return ETH_P_ARCNET; } 
        else if(!strcmp(str, "DSA")) { return ETH_P_DSA; } 
        else if(!strcmp(str, "TRAILER")) { return ETH_P_TRAILER; } 
        else if(!strcmp(str, "PHONET")) { return ETH_P_PHONET; } 
        else if(!strcmp(str, "IEEE802154")) { return ETH_P_IEEE802154; } 
        else if(!strcmp(str, "CAIF")) { return ETH_P_CAIF; } 
        else if(!strcmp(str, "XDSA")) { return ETH_P_XDSA; } 
        else if(!strcmp(str, "MAP")) { return ETH_P_MAP; } 
        else return -1;
}


void    print_if(void) {
        printf("Interfaces : \n");
        struct ifaddrs *ifaddr, *ifaddrtmp;
        struct sockaddr_in *inaddr;
        getifaddrs(&ifaddr);
        ifaddrtmp = ifaddr;
        while(ifaddr) {
                printf("  -> %s ", ifaddr->ifa_name);
                inaddr = (struct sockaddr_in *) ifaddr->ifa_addr;
                if(inaddr->sin_family == AF_INET)
                        printf("- %s", inet_ntoa(inaddr->sin_addr));
                ifaddr = ifaddr->ifa_next;
                printf("\n");
        }
        freeifaddrs(ifaddrtmp);
        printf("\n");
}


void    liste_init(size_t elem_len, struct liste *li) {
        li->first = NULL;
        li->last = NULL;
        li->elem_len = elem_len;
}

struct liste_elem* liste_insert(void *obj, struct liste *li) {
        struct liste_elem *elem = NULL;
        
        elem = (struct liste_elem *) malloc(sizeof(struct liste_elem));
        __C(elem, NULL, "liste_insert: plus de mémoire ");
        
        if(li->last)
                li->last->next = elem;
        
        elem->liste = li;
        elem->next = NULL;
        elem->prev = li->last;
        elem->contenu = obj;
        
        li->last = elem;
        if(!li->first)
                li->first = elem;
        
        return elem;
}

void*   liste_supprimer(struct liste_elem *elem) {
        void *obj = elem->contenu;
        
        if(elem->prev)
                elem->prev->next = elem->next;
        else
                elem->liste->first = elem->next;
        
        if(elem->next)
                elem->next->prev = elem->prev;
        else
                elem->liste->last = elem->prev;
        
        free(elem);
        return obj;
}

void*   liste_suppr_obj(void *obj, struct liste *li) {
        struct liste_elem *next_el = li->first;
        
        while(next_el) {
                if(next_el->contenu == obj) 
                        return liste_supprimer(next_el);
                else
                        next_el = next_el->next;
        }
        return NULL;
}

void *  liste_rechercher_obj(void *srch, size_t start, size_t len, struct liste *li) {
        struct liste_elem *next_el = li->first;
        
        while(next_el) {
                if(memcmp(next_el->contenu + start, srch, len) == 0)
                        return next_el->contenu;
                else
                        next_el = next_el->next;
        }
        return NULL;
}

int     liste_vide(struct liste *li) {
        return li->first == NULL;
}

unsigned int liste_size(struct liste *li) {
        int i = 0;
        struct liste_elem *next_el = li->first;
        
        while(next_el) {
                next_el = next_el->next;
                i++;
        }
        return i;
}

void    liste_foreach(struct liste *li, void (*run)(void *obj)) {
        struct liste_elem *next_el = li->first;
        
        while(next_el) {
                (*run)(next_el->contenu);
                next_el = next_el->next;
        }
}

void    liste_destroy(struct liste *li) {
        struct liste_elem *next = li->first;
        struct liste_elem *next_tmp;
        void *obj;
        
        while(next) {
                next_tmp = next->next;
                obj = liste_supprimer(next);
                if(obj) free(obj);
                next = next_tmp;
        }
}



void    compteur_start(struct compteur *c) {
        if(clock_gettime(CLOCK_REALTIME, &(c->debut)) < 0)
                perror("compteur_start: erreur ");
}


void    compteur_end(struct compteur *c) {
        long sec,
             nsec;

        if(clock_gettime(CLOCK_REALTIME, &(c->fin)) < 0)
                perror("compteur_end: erreur ");
        else {
                sec = c->fin.tv_sec - c->debut.tv_sec;
                nsec = c->fin.tv_nsec - c->debut.tv_nsec;
                c->duree = sec * 1000 + (long)((double)nsec/1e6);
        }
}



