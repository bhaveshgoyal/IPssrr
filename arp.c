#include	"hw_addrs.h"
#include "unp.h"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <netinet/ip.h>
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>
#define ARPOP_RESPONSE 2   // Taken from <linux/if_arp.h>

//char *P_IP = "130.245.156.1";
char *P_IP = "172.24.28.162";
char iface[10];

char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int lookup_loifaces(char *lo_ip, uint8_t *lo_mac){

	struct hwa_info	*hwa, *hwahead;
	struct sockaddr	*sa;
	char   *ptr;
	int    i, prflag;

	printf("\n");

	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {

			if ( (sa = hwa->ip_addr) != NULL && strstr(Sock_ntop_host(sa, sizeof(*sa)), P_IP) != NULL){
					printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
					
					printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));
					strcpy(lo_ip, Sock_ntop_host(sa, sizeof(*sa)));
					strcpy(iface, hwa->if_name);

					prflag = 0;
					i = 0;
					do {
							if (hwa->if_haddr[i] != '\0') {
									prflag = 1;
									break;
							}
					} while (++i < IF_HADDR);

					char hw_addr[100] = {0};
					if (prflag) {
							printf("         HW addr = ");
							ptr = hwa->if_haddr;
                            memcpy(lo_mac, ptr, 6*sizeof(uint8_t));
							i = IF_HADDR;
							do {
									char addr_str[10];
									sprintf(addr_str, "%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
									strcat(hw_addr, addr_str);
							} while (--i > 0);
							hw_addr[strlen(hw_addr)] = '\0';
					}
					printf("%s", hw_addr);

					printf("\n         interface index = %d\n\n", hwa->if_index);
					free_hwa_info(hwahead);
					return hwa->if_index;
			}
	}
	return -1;
}

int send_response(uint8_t *ethr_frame, arp_hdr *arpheader)
{
  int i, status, frame_length, sd, bytes;
  char *interface, *query, *src_ip, *sender_ip;
  arp_hdr arphdr;
  uint8_t *src_mac, *sender_mac,  *dst_mac, *ether_frame;
//  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;

	
  src_mac = allocate_ustrmem (6);
  sender_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  query = allocate_strmem (40);
  sender_ip = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
//  lookup_loifaces(src_ip, src_mac);

	memset (&device, 0, sizeof (device));
	
	if ((device.sll_ifindex = lookup_loifaces(src_ip, src_mac)) < 0){
			perror("Failed to obtain an index");
			exit (EXIT_FAILURE);
	}


    memcpy(dst_mac, ethr_frame, 6 * sizeof (uint8_t));
    memcpy(query, arpheader->target_ip, 4*sizeof(uint8_t));
    sprintf(query, "%u.%u.%u.%u", arpheader->target_ip[0], arpheader->target_ip[1], arpheader->target_ip[2], arpheader->target_ip[3]);
    sprintf(sender_ip, "%u.%u.%u.%u", arpheader->sender_ip[0], arpheader->sender_ip[1], arpheader->sender_ip[2], arpheader->sender_ip[3]);
    if (strcmp(query, src_ip) != 0){
        printf("None of my business\n");
        free(src_mac);
        free(dst_mac) ;
        free(ether_frame);
        free(query);
        free(src_ip);
        free(sender_ip);
        free(sender_mac);
        return -1;
    }

    //  memset (&hints, 0, sizeof (struct addrinfo));

//  hints.ai_family = AF_INET;
//  hints.ai_socktype = SOCK_STREAM;
//  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

    if ((status = inet_pton (AF_INET, src_ip, &arphdr.sender_ip)) != 1) {
      fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
      exit (EXIT_FAILURE);
  }
  
  memcpy (&arphdr.target_ip, arpheader->sender_ip, 4 * sizeof (uint8_t));
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;
  device.sll_hatype = ARPHRD_ETHER;
    
    FILE * fp, *fp_out;
    char * line = NULL;
    char line_found[100] = {0};
    size_t len = 0;
    ssize_t read;
    fp = fopen("bagl.log", "r");
    fp_out = fopen("bagl.log.2", "w+");

    while ((read = getline(&line, &len, fp)) != -1) {
        if (strstr(line, sender_ip) != NULL){
            strcpy(line_found, line);
            printf("Cache entry found: %s\n", line);
        }
        else {
            fprintf(fp_out, "%s", line);
        }
    }
    sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arpheader->sender_mac[0],arpheader->sender_mac[1],arpheader->sender_mac[2],arpheader->sender_mac[3],arpheader->sender_mac[4],arpheader->sender_mac[5]); 
    char log_str[100];
    sprintf(log_str, "<%s, %s, %d, %d>", sender_ip, sender_mac, device.sll_ifindex, device.sll_hatype);
    fprintf(fp_out, "%s", log_str);
    fclose(fp);
    fclose(fp_out);

    rename("bagl.log.2", "bagl.log");
    

  // Hardware type (16 bits): 1 for ethernet
  arphdr.htype = htons (1);

  // Protocol type (16 bits): 2048 for IP
  arphdr.ptype = htons (ETH_P_IP);

  // Hardware address length (8 bits): 6 bytes for MAC address
  arphdr.hlen = 6;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr.plen = 4;

  // OpCode: 1 for ARP request
  arphdr.opcode = htons (ARPOP_RESPONSE);

  // Sender hardware address (48 bits): MAC address
  memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

  // Sender protocol address (32 bits)
  // See getaddrinfo() resolution of src_ip.

  // Target hardware address (48 bits): zero, since we don't know it yet.
  memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  // Target protocol address (32 bits)
  // See getaddrinfo() resolution of target.

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
  frame_length = 6 + 6 + 2 + ARP_HDRLEN;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;

  // Next is ethernet frame data (ARP header).

  // ARP header
  memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
  }

  printf ("\nEthernet Response frame header:\n");
  printf ("Destination MAC: ");
  for (i=0; i<5; i++) {
      printf ("%02x:", ether_frame[i]);
  }
  printf ("%02x\n", ether_frame[5]);
  printf ("Source MAC: ");
  for (i=0; i<5; i++) {
      printf ("%02x:", ether_frame[i+6]);
  }
  printf ("%02x\n", ether_frame[11]);
  printf ("ARP, Reply ");
  printf ("%u.%u.%u.%u (",
          arpheader->target_ip[0], arpheader->target_ip[1], arpheader->target_ip[2], arpheader->target_ip[3]);
  for (i=0; i<5; i++) {
      printf ("%02x:", arpheader->target_mac[i]);
  }
  printf ("%02x) ", arpheader->target_mac[5]);
  printf ("is-at %s (", src_ip);
  for (i=0; i<5; i++) {
      printf ("%02x:", src_mac[i]);
  }
  printf ("%02x)\n", src_mac[5]);

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (query);
  free (src_ip);
  free(sender_ip);
  free(sender_mac);
  return (EXIT_SUCCESS);
}
int main(int arc, char **argv){

  int i, sd, status;
  uint8_t *ether_frame;
  arp_hdr *arphdr;

  // Allocate memory for various arrays.
  ether_frame = allocate_ustrmem (IP_MAXPACKET);

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Listen for incoming ethernet frame from socket sd.
  // We expect an ARP ethernet frame of the form:
  //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
  //     + ethernet data (ARP header) (28 bytes)
  // Keep at it until we get an ARP reply.
  arphdr = (arp_hdr *) (ether_frame + 6 + 6 + 2);
//  while (((((ether_frame[12]) << 8) + ether_frame[13]) != ETH_P_ARP) || (ntohs (arphdr->opcode) != ARPOP_REQUEST)) {
  while(1){
      if ((status = recv(sd, ether_frame, IP_MAXPACKET, 0)) < 0) {
          if (errno == EINTR) {
              memset (ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
              continue;  // Something weird happened, but let's try again.
          } else {
              perror ("recv() failed:");
              exit (EXIT_FAILURE);
          }
      }
      else{
          if (ntohs(arphdr->opcode) == ARPOP_REQUEST){

              printf ("\nEthernet Request frame header:\n");
              printf ("Destination MAC: ");
              for (i=0; i<5; i++) {
                  printf ("%02x:", ether_frame[i]);
              }
              printf ("%02x\n", ether_frame[5]);
              printf ("Source MAC: ");
              for (i=0; i<5; i++) {
                  printf ("%02x:", ether_frame[i+6]);
              }
              printf ("%02x\n", ether_frame[11]);
              printf ("ARP, Request who-has ");
              printf ("%u.%u.%u.%u (",
                      arphdr->target_ip[0], arphdr->target_ip[1], arphdr->target_ip[2], arphdr->target_ip[3]);
              for (i=0; i<5; i++) {
                  printf ("%02x:", arphdr->target_mac[i]);
              }
              printf ("%02x) ", arphdr->target_mac[5]);
              printf ("tell: %u.%u.%u.%u (",
                      arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);

              for (i=0; i<5; i++) {
                  printf ("%02x:", arphdr->sender_mac[i]);
              }
              printf ("%02x)\n", arphdr->sender_mac[5]);

              send_response(ether_frame, arphdr);
              fflush(stdout);
        }


    }
  }
  close (sd);

  // Print out contents of received ethernet frame.
  printf ("\nEthernet frame header:\n");
  printf ("Destination MAC (this node): ");
  for (i=0; i<5; i++) {
    printf ("%02x:", ether_frame[i]);
  }
  printf ("%02x\n", ether_frame[5]);
  printf ("Source MAC: ");
  for (i=0; i<5; i++) {
    printf ("%02x:", ether_frame[i+6]);
  }
  printf ("%02x\n", ether_frame[11]);
  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  printf ("Ethernet type code (2054 = ARP): %u\n", ((ether_frame[12]) << 8) + ether_frame[13]);

}    
    
    
    
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

