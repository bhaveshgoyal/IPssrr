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
#define ARP_PID 6157
//char *P_IP = "130.245.156.1";
char iface[10];
char lo_ip[50];
uint8_t src_mac[6];
int ifidx = -1;
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int lookup_loifaces(char *lo_ip, uint8_t *lo_mac, char *host);
void slice_str(const char * str, char * buffer, size_t start, size_t end)
{
    size_t j = 0;
    for ( size_t i = start; i <= end; ++i ) {
        buffer[j++] = str[i];
    }
    buffer[j] = 0;
}
int issue_arp(uint8_t *ethr_frame, arp_hdr *arpheader, int arp_type, char *resp_mac)
{
  int i, status, frame_length, sd, bytes;
  arp_hdr arphdr;
  uint8_t *sender_mac,  *dst_mac, *ether_frame;
//  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;

	
  sender_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);

	memset (&device, 0, sizeof (device));
	device.sll_ifindex = ifidx;

    memcpy(dst_mac, ethr_frame, 6 * sizeof (uint8_t));


	if ((status = inet_pton (AF_INET, lo_ip, &arphdr.sender_ip)) != 1) {
			fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
			exit (EXIT_FAILURE);
	}

	memcpy (&arphdr.target_ip, arpheader->sender_ip, 4 * sizeof (uint8_t));
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;
  device.sll_hatype = ARPHRD_ETHER;
    

  // Hardware type (16 bits): 1 for ethernet
  arphdr.htype = htons (1);

  // Protocol type (16 bits): 2048 for IP
  arphdr.ptype = htons (ETH_P_IP);

  // Hardware address length (8 bits): 6 bytes for MAC address
  arphdr.hlen = 6;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr.plen = 4;

  // OpCode: 1 for ARP request
  arphdr.opcode = htons (arp_type);

  // Sender hardware address (48 bits): MAC address
  memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

  // Sender protocol address (32 bits)
  // See getaddrinfo() resolution of src_ip.

  // Target hardware address (48 bits): zero, since we don't know it yet.
  if (arp_type == ARPOP_REQUEST)
  	memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));
  else{
  	int target_temp[6];
  	uint8_t target_mac[6];
	sscanf(resp_mac, "%x:%x:%x:%x:%x:%x%*c", &target_temp[0], &target_temp[1], &target_temp[2], &target_temp[3], &target_temp[4], &target_temp[5]);
	for(int i =0; i < 6; i++)
		target_mac[i] = (uint8_t)target_temp[i];
	memcpy(&arphdr.target_mac, target_mac, 6 * sizeof (uint8_t));
  
  }
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
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ARP_PID))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (dst_mac);
  free (ether_frame);
  free(sender_mac);
  return (EXIT_SUCCESS);
}
int main(int arc, char **argv){

  int i, sd, status;
  uint8_t *ether_frame;
  arp_hdr *arphdr;


  struct hostent* hen;
  char hostname[1024];
  hostname[1023] = '\0';
  gethostname(hostname, 1023);
  hen = gethostbyname(hostname);
  printf("h_name: %s\n", hen->h_name);
  if ((ifidx = lookup_loifaces(lo_ip, src_mac, hen->h_name)) < 0){
		  perror("Could not find device interface");
		  return 0;
  }
  // Allocate memory for various arrays.
  ether_frame = allocate_ustrmem (IP_MAXPACKET);

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ARP_PID))) < 0) {
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
  int unfd;
  struct sockaddr_un unservaddr, uncliaddr;
  socklen_t clilen;

  unfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
  
  unlink(UNIXSTR_PATH);
  bzero(&unservaddr, sizeof(unservaddr));

  unservaddr.sun_family = AF_LOCAL;
  strcpy(unservaddr.sun_path, UNIXSTR_PATH);

  Bind(unfd, (SA *) &unservaddr, sizeof(unservaddr));
  Listen(unfd, LISTENQ);
  
  
  fd_set readfs;
  FD_SET(unfd, &readfs);
  FD_SET(sd, &readfs);
  int maxfd = -1;
  while(1){

		  FD_ZERO(&readfs);
		  FD_SET(sd, &readfs);
		  FD_SET(unfd, &readfs);
		  maxfd = max(sd, unfd);

		  int status = select(maxfd+1, &readfs, NULL, NULL, NULL);
		  if (status < 0)
				  continue;

		  if (FD_ISSET(unfd, &readfs)){
		  			int unconn  = accept(unfd, (SA *) &uncliaddr, &clilen);
				char query_line[MAXLINE];
		 		if ( (Read(unconn, query_line, MAXLINE)) == 0) {
		  		fprintf(stdout, "Socket SET");
				fflush(stdout);
					continue;
				
				}
				fprintf(stdout, "Query: %s", query_line);
				fflush(stdout);
		  
		  }
		  else if (FD_ISSET(sd, &readfs)){
				  if (recv(sd, ether_frame, IP_MAXPACKET, 0) < 0) {
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

								  char query[50] = {0};
								  char sender_ip[50] = {0};
								  char sender_mac[50] = {0};

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

								  sprintf (query, "%u.%u.%u.%u",
												  arphdr->target_ip[0], arphdr->target_ip[1], arphdr->target_ip[2], arphdr->target_ip[3]);
								  printf("%s (", query);

								  for (i=0; i<5; i++) {
										  printf ("%02x:", arphdr->target_mac[i]);
								  }
								  printf ("%02x) tell:", arphdr->target_mac[5]);

								  sprintf (sender_ip, "%u.%u.%u.%u",
												  arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
								  printf("%s ", sender_ip);

								  sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arphdr->sender_mac[0],arphdr->sender_mac[1],arphdr->sender_mac[2],arphdr->sender_mac[3],arphdr->sender_mac[4],arphdr->sender_mac[5]); 
								  printf ("(%s)\n", sender_mac);

								  //Check local Cache
								  FILE * fp, *fp_out;
								  char * line = NULL;
								  char resp_mac[100] = {0};
								  char cache_res[100] = {0};
								  int res_me = 0;
								  int res_else = 0;
								  size_t len = 0;
								  ssize_t read;
								  fp = fopen("bagl.log", "r");
								  fp_out = fopen("bagl.log.2", "w+");
								  if (strcmp(lo_ip, query) == 0){
										  res_me = 1; // I am the queried node
								  }
								  while (fp != NULL && (read = getline(&line, &len, fp)) != -1) {

										  char line_ip[50] = {0};
										  char copy_line[100] = {0};
										  strcpy(copy_line, line);
										  char *temp_line = strtok(line, ",");
										  slice_str(temp_line, line_ip, 1, strlen(temp_line)-1);

										  if (strcmp(line_ip, sender_ip) == 0){ 
												  printf("Sender Query IP Found in Cache: %s\n", copy_line); 
												  res_me = 1;
										  }
										  else if (strcmp(line_ip, query) == 0){
												  strcpy(cache_res, copy_line);
												  printf("Cache entry found: %s\n", copy_line);
												  fprintf(fp_out, "%s", copy_line);
												  res_else = 1;
										  }
										  else {
												  fprintf(fp_out, "%s", copy_line);
										  }
								  }
								  if (res_me){
										  char log_str[100];
										  //TODO Fix this index
										  strcpy(resp_mac, src_mac);
										  sprintf(log_str, "<%s,%s,%d,%d>\n", sender_ip, sender_mac, ifidx, arphdr->htype);
										  fprintf(fp_out, "%s", log_str);
								  }
								  else if (res_else){
										  strtok(cache_res, ",");
										  strcpy(resp_mac, strtok(NULL, "\n"));
								  }
								  if (fp)
										  fclose(fp);
								  fclose(fp_out);

								  rename("bagl.log.2", "bagl.log");


								  if (res_me || res_else)
										  issue_arp(ether_frame, arphdr, ARPOP_RESPONSE, resp_mac);
								  else
										  issue_arp(ether_frame, arphdr, ARPOP_REQUEST, resp_mac);
								  fflush(stdout);
						  }
						  else if (ntohs(arphdr->opcode) == ARPOP_RESPONSE){


								  char target_mac[100] = {0};
								  char target_ip[100] = {0};
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
								  sprintf (target_ip, "%u.%u.%u.%u",
												  arphdr->target_ip[0], arphdr->target_ip[1], arphdr->target_ip[2], arphdr->target_ip[3]);
								  printf("%s ", target_ip);

								  sprintf(target_mac, "%02x:%02x:%02x:%02x:%02x:%02x", arphdr->target_mac[0],arphdr->target_mac[1],arphdr->target_mac[2],arphdr->target_mac[3],arphdr->target_mac[4],arphdr->target_mac[5]); 
								  printf ("(%s) ", target_mac);

								  printf ("is-at %s (", lo_ip);
								  for (i=0; i<5; i++) {
										  printf ("%02x:", src_mac[i]);
								  }

								  FILE * fp;
								  fp = fopen("bagl.log", "a+");
								  char log_str[100];
								  //TODO Fix this index
								  sprintf(log_str, "<%s,%s,%d,%d>\n", target_ip, target_mac, ifidx, arphdr->htype);
								  fprintf(fp, "%s", log_str);
								  fclose(fp);

								  //Send to tour back  TODO
						  }
				  }
		  }
  }
  close (sd);

}    
    
