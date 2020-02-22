#ifndef H_UTIL
#define H_UTIL

#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdlib.h>

#define DUMP_NB_COL     4
#define __C(var, val, msg) if((var) == val) { perror(msg); exit(EXIT_FAILURE);}


struct  compteur {
        struct timespec debut,
                        fin;
        long duree;
};

struct liste_elem {
        struct liste      *liste;
        struct liste_elem *next;
        struct liste_elem *prev;
        void * contenu;
};

struct liste {
        size_t elem_len;
        struct liste_elem* first;
        struct liste_elem* last;
};

void    hex_dump(void *buf, size_t len);
void    fill_blank(const char *str, int size_total);

void    reverse_dns_lookup(struct in_addr *addr);
void    dns_lookup(const char *domain, struct sockaddr_in *target);

/* Calcul checksum pour ethernet */
uint16_t calcul_checksum_16(void * obj, size_t len);

/* Créé une socket selon l'interface et le protocole donnée */
int     socket_open_raw_packet(const char *ifname, struct ifreq *ifr, int proto);

/* Protocole -> ethertype. str en majuscule. par ex: ARP ou IP */
int     str_to_proto(char *str);

/* Afficher les interfaces réseau dispo */
void    print_if(void);

/* Liste chainée */
void                liste_init(size_t elem_len, struct liste *li);
struct  liste_elem* liste_insert(void *obj, struct liste *li);
void*               liste_supprimer(struct liste_elem *elem);
void*               liste_suppr_obj(void *obj, struct liste *li);
void*               liste_rechercher_obj(void *srch, size_t start, size_t len, struct liste *li);
int                 liste_vide(struct liste *li);
unsigned int        liste_size(struct liste *li);
void                liste_foreach(struct liste *li, void (*run)(void *obj));
void                liste_destroy(struct liste *li);

void    compteur_start(struct compteur *c);
void    compteur_end(struct compteur *c);

#endif

