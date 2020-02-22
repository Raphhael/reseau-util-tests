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

#define  BUFFER_SIZE  1024

void    uping(int sockfd, struct sockaddr_in *target, int id) {
        
        struct timespec debut, fin;
        
        long sec, nsec;
        
        clock_gettime(CLOCK_REALTIME, &debut);
        icmp_send(sockfd, target, 0);
        icmp_recv(sockfd, NULL, NULL);
        clock_gettime(CLOCK_REALTIME, &fin);
        
        sec = fin.tv_sec - debut.tv_sec;
        nsec = fin.tv_nsec - debut.tv_nsec;
        
        printf("ping %d : %ld ms\n", id, sec * 1000 + (long)((double)nsec/1e6));
}

int     main(int argc, char *argv[]) {
        if(argc < 3) {
                fprintf(stderr, "Syntaxe : %s server(sans http://) nb_ping\n", *argv);
                return EXIT_FAILURE;
        }
        
        int                 sockfd;
        struct sockaddr_in  target;
        
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        __C(sockfd, -1, "Impossible de créer la socket "); 
        
        dns_lookup(argv[1], &target);
        
        printf("---> ");
        reverse_dns_lookup(&target.sin_addr);
        printf("\n");
        
        for(int i = 1; i <= atoi(argv[2]); i++)
                uping(sockfd, &target, i);
        
        return EXIT_SUCCESS;
}


