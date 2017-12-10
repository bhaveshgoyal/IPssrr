/* Our own header for the programs that need hardware address info. */

#include <stdio.h>
#include <sys/socket.h>

#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

typedef struct _arp_hdr arp_hdr;
typedef unsigned short uint16_t;
typedef          short  int16_t;
typedef unsigned char   uint8_t;

struct hwa_info {
  char    if_name[IF_NAME];	/* interface name, null terminated */
  char    if_haddr[IF_HADDR];	/* hardware address */
  int     if_index;		/* interface index */
  short   ip_alias;		/* 1 if hwa_addr is an alias IP address */
  struct  sockaddr  *ip_addr;	/* IP address */
  struct  hwa_info  *hwa_next;	/* next of these structures */
};

struct hwaddr {
    int             sll_ifindex;     /* Interface number */
    unsigned short  sll_hatype;    /* Hardware type */
    unsigned char   sll_halen;   /* Length of address */
    unsigned char   sll_addr[8];     /* Physical layer address */
};

/* function prototypes */
struct hwa_info	*get_hw_addrs();
struct hwa_info	*Get_hw_addrs();
void	free_hwa_info(struct hwa_info *);



struct _arp_hdr {
		uint16_t htype;
		uint16_t ptype;
		uint8_t hlen;
		uint8_t plen;
		uint16_t opcode;
		uint8_t sender_mac[6];
		uint8_t sender_ip[4];
		uint8_t target_mac[6];
		uint8_t target_ip[4];
};

typedef struct proto {
    struct sockaddr  *sasend;   /* sockaddr{} for send, from getaddrinfo */
    struct sockaddr  *sarecv; /* sockaddr{} for receiving */
    socklen_t       salen;      /* length of sockaddr{}s */
    int           proto_val;  /* IPPROTO_xxx value for ICMP */
} proto;
