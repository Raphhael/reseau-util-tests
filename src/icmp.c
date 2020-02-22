#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "../header/util.h"
#include "../header/icmp.h"

#define ICMP_BUFFER_SIZE        1024

void    icmp_init(struct icmp *header, uint8_t type) {
        memset((struct icmp *) header, 0, sizeof(struct icmp));
        header->icmp_type = type;
        header->icmp_cksum = calcul_checksum_16(header, sizeof(struct icmp));
}

void    icmp_send(int sockfd, struct sockaddr_in *to, int ttl) {
        struct  icmp  header;
        
        if(ttl)
                __C(  setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(int)),
                                        -1, "Impossible de mettre le TTL ");
        
        icmp_init(&header, ICMP_ECHO);
        
        __C(sendto(sockfd, &header, sizeof(struct icmp), 0,
                (struct sockaddr *) to, sizeof(struct sockaddr_in))
            , -1, "Echec de l'envoi de données ");
}

void    icmp_recv(int sockfd, struct icmp *icmp_response, struct ip *ip_response) {
        ssize_t       recu;
        char          buffer[ICMP_BUFFER_SIZE];
        
        recu = recvfrom(sockfd, &buffer, ICMP_BUFFER_SIZE * sizeof(char), 0, NULL, NULL);
        
        if(recu == -1) {
                if(errno != EAGAIN) {
                        __C(recu, -1, "Echec dans le recv de l'entete IP");
                } else
                        printf(" Temps écoulé "); 
                return ;
        }
        
        printf(" [%ld octets recus] ", recu);
        
        if(!icmp_response || !ip_response)
                return ;
        
        if(recu >= sizeof(struct ip)) {
                memcpy((struct ip *)ip_response, (char *)buffer, sizeof(struct ip));
                
                reverse_dns_lookup( &ip_response->ip_src);
                
                printf("%s\t", inet_ntoa(ip_response->ip_src));
                
                if(recu >= sizeof(struct ip) + sizeof(struct icmp))
                        memcpy((struct icmp *)icmp_response, (char *)(buffer + sizeof(struct ip)), sizeof(struct icmp));
                else
                        printf("Paquet ICMP reçu illisible ...");
        }
        else {
                printf("Paquet IP reçu illisible ...");
        }

}
