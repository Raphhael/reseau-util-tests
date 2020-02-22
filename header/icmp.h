#ifndef H_ICMP
#define H_ICMP

void    icmp_init(struct icmp *header, uint8_t type);
void    icmp_send(int sockfd, struct sockaddr_in *to, int ttl) ;
void    icmp_recv(int sockfd, struct icmp *icmp_response, struct ip *ip_response);

#endif

