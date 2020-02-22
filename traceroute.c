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

#include "header/util.h"
#include "header/icmp.h"

#define         MAX_TTL                 40
#define         MAX_RECV_SEC            1
#define         MAX_RECV_MICROSEC       0

void    add_opt(int sockfd) {
        struct timeval expire;
        memset((struct timeval *) &expire, 0, sizeof(struct timeval));
        expire.tv_sec = MAX_RECV_SEC;
        expire.tv_usec = MAX_RECV_MICROSEC;
        
        __C(
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &expire, sizeof(struct timeval)), -1,
                "Impossible de mettre le max time "
        );
}

void    utraceroute(int sockfd, struct sockaddr_in *target) {
        int ttl = 0;
        struct icmp     icmp_response;
        struct ip       ip_response;
        struct compteur timer;
        
        do {
                ttl++;
                printf(" %d ", ttl);
                
                compteur_start(&timer);
                
                icmp_send(sockfd, target, ttl);
                icmp_recv(sockfd, &icmp_response, &ip_response);
        
                compteur_end(&timer);
                printf("\t%ld ms", timer.duree);
                
                printf("\n");
        }
        while(  ttl < MAX_TTL
                && icmp_response.icmp_type == 11 && icmp_response.icmp_code == 0
              );
}

int     main(int argc, char *argv[]) {
        if(argc < 2) {
                fprintf(stderr, "Syntaxe : %s server(sans http://)\n", *argv);
                return EXIT_FAILURE;
        }
        
        int                     sockfd;
        struct sockaddr_in      target;
        
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        __C(sockfd, -1, "Impossible de créer la socket ");
        
        dns_lookup(argv[1], &target);
        add_opt(sockfd);
        
        utraceroute(sockfd, &target);
        
        return EXIT_SUCCESS;
}


