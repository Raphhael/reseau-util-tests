#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>

#include "header/util.h"

#define BUFFER_LEN      2<<15
#define SYNTAXE         "Syntaxe : %s PROTOCOL interface\n"

int     sortir;

void    quitter(int sig) {
        sortir = 1;
}

int     main(int argc, char *argv[]) {
        if(argc < 2) {
                fprintf(stderr, SYNTAXE, *argv);
                print_if();
                return EXIT_FAILURE;
        }

        struct ifreq        ifr;
        struct ether_header *hdr;
        struct ip           *ip_hdr;
        char       buffer[BUFFER_LEN];
        ssize_t    bytes;
        uint16_t   type;
        int        pktfd;
        int        proto = str_to_proto(argv[1]);
        
        signal(SIGINT, quitter);
        
        __C(proto, -1, "Protocole inconnu !");
        
        pktfd = socket_open_raw_packet(argv[2], &ifr, proto);
        
        /* hdr pointe sur le début du buffer */
        hdr    = (struct ether_header *)buffer;
        ip_hdr = (struct ip *) (sizeof(struct  ether_header) + buffer);
        
        
        while(!sortir) {
                /* attente de trames */
                bytes = recv(pktfd, buffer, BUFFER_LEN, 0);
                __C(bytes, -1, "problème dans la reception de données ");

                type = ntohs(hdr->ether_type);
                
                printf("Type : %.4x\n", type);
                printf("@src : %s\n", ether_ntoa((struct ether_addr *)&hdr->ether_shost));
                printf("@dst : %s\n", ether_ntoa((struct ether_addr *)&hdr->ether_dhost));
                
                if(type == ETHERTYPE_IP) {
                        printf("IP src : %s ", inet_ntoa(ip_hdr->ip_src));
                                //reverse_dns_lookup(ip_hdr->ip_src);
                        printf("\nIP dst : %s ", inet_ntoa(ip_hdr->ip_dst));
                                //reverse_dns_lookup(ip_hdr->ip_dst);
                        printf("\n");
                }
                
                hex_dump(buffer, bytes);
                printf("\n--------------------------------------------------------------------------------\n");
        }
        
        printf("Fin ...\n");
        close(pktfd);
        return EXIT_SUCCESS;
}
