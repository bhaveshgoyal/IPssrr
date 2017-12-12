#include "unp.h"
#include "hw_addrs.h"
#include    <netinet/ip_icmp.h>
#include <linux/if_ether.h>                                                                       
#include <linux/if_packet.h>
// Send an IPv4 ICMP echo request packet via raw socket at the link layer (ethernet frame),
// and receive echo reply packet (i.e., ping). Includes some ICMP data.
// Need to have destination MAC address.

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t icmp4_checksum (struct icmp, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);
int pid = 157;

int arpwait = 5;

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr);
int
send_icmpp(char *srcip, uint8_t *srcmac, int ifidx, char *dstip)
{
  int i, status, datalen, frame_length, sendsd, bytes, *ip_flags;
 // timeout, trycount, trylim, done;
  char *src_ip, *dst_ip;
  struct ip send_iphdr;
  struct icmp send_icmphdr;
  uint8_t *data, *src_mac, *dst_mac, *send_ether_frame;
  struct sockaddr_ll device;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  // Interface to send packet through.
  // We'll use it to send packets as well, so we leave it open.
  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  memset (&device, 0, sizeof (device));

  device.sll_ifindex = ifidx;
  strcpy(src_ip, srcip);
  memcpy(src_mac, srcmac, 6*sizeof(uint8_t));
  fprintf(stdout, "INSIDE ICMP: %s %s\n", src_ip, dstip);
  fflush(stdout);
//#TODO Find This using AREQ

	struct sockaddr_in quer_addr;
	struct hwaddr target_hw; 
	socklen_t querylen = sizeof(quer_addr);
	inet_pton(AF_INET, dstip, &(quer_addr.sin_addr));
	int ret = areq((struct sockaddr *)&quer_addr, querylen, &target_hw);
//	if (ret < 0){
//			fprintf(stderr, "MAC couldn't be found using ARP. Retrying using broadcast\n");
			dst_mac[0] = 0xff;
			dst_mac[1] = 0xff;
			dst_mac[2] = 0xff;
			dst_mac[3] = 0xff;
			dst_mac[4] = 0xff;
			dst_mac[5] = 0xff;

//	}
//	else {
//		int tempdst_mac[6];
//		sscanf(target_hw.sll_addr,"%02x%02x%02x%02x%02x%02x", &tempdst_mac[0], &tempdst_mac[1], &tempdst_mac[2], &tempdst_mac[3], &tempdst_mac[4], &tempdst_mac[5]);
//		for(int i = 0; i < 5; i++){
//			dst_mac[i] = (uint8_t)target_hw.sll_addr[i];
//			fprintf(stdout, "UTIL: %02x:", dst_mac[i]);
//			fflush(stdout);
//		}
//	}

  // Source IPv4 address: you need to fill this out
//  strcpy (target, "www.google.com");

  // Fill out hints for getaddrinfo().
  strcpy(dst_ip, dstip);
  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  datalen = 4;
  data[0] = 'P';
  data[1] = 'I';
  data[2] = 'N';
  data[3] = 'G';

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  send_iphdr.ip_v = 4;

  // Type of service (8 bits)
  send_iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  send_iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  send_iphdr.ip_id = rand();

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  send_iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  send_iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  send_iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  send_iphdr.ip_sum = 0;
  send_iphdr.ip_sum = checksum ((uint16_t *) &send_iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  send_icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): echo request
  send_icmphdr.icmp_code = 0;


  // Identifier (16 bits): usually pid of sending process - pick a number
  send_icmphdr.icmp_id = pid & 0xffff;

  // Sequence Number (16 bits): starts at 0
  send_icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;

  // Destination and Source MAC addresses
  memcpy (send_ether_frame, dst_mac, 6);
  memcpy (send_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  send_ether_frame[12] = ETH_P_IP / 256;
  send_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

  // IPv4 header
  memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);


  // Send ethernet frame to socket.
  if ((bytes = sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
		  perror ("sendto() failed ");
		  exit (EXIT_FAILURE);
  }


  // Close socket descriptors.
  close (sendsd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (send_ether_frame);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

  return (EXIT_SUCCESS);
}

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr){

	int unfd;
	struct sockaddr_un unservaddr;
	unfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

	char *UND_PATH = "/home/bgoyal/bagl.und";
	struct sockaddr_in *query = (struct sockaddr_in *)IPaddr;
	char str[50] = {0};
	inet_ntop(AF_INET, &(query->sin_addr), str, INET_ADDRSTRLEN);
	bzero(&unservaddr, sizeof(unservaddr));
	unservaddr.sun_family = AF_LOCAL;
	strcpy(unservaddr.sun_path, UND_PATH);
	Connect(unfd, (SA *) &unservaddr, sizeof(unservaddr));
	
	Write(unfd, str, sizeof(str)); //Query the server
	
	fd_set readfs;


	FD_ZERO(&readfs);
	FD_SET(unfd, &readfs);
	int maxfd = unfd;
	
	while(1){

		FD_ZERO(&readfs);
		FD_SET(unfd, &readfs);
		maxfd = unfd;

		struct timeval tv = {5, 0};
		if (select(maxfd+1, &readfs, NULL, NULL, &tv) < 0){
			fprintf(stderr, "AREQ Timed out.\n");
			return -1;
		}
		if (FD_ISSET(unfd, &readfs)){
			char resp_mac[50] = {0};
			if (read(unfd, resp_mac, sizeof(resp_mac)) == 0){
				return 1;
			}
			fprintf(stdout, "AREQ Response Received: %s\n", resp_mac);
			fflush(stdout);
			int target_dstmac[6];
			sscanf(resp_mac, "%x%x%x%x%x%x%*c", &target_dstmac[0], &target_dstmac[1], &target_dstmac[2], &target_dstmac[3], &target_dstmac[4], &target_dstmac[5]);
			for(int i = 0; i < 6; i++)
				HWaddr->sll_addr[i] = (uint8_t)target_dstmac[i];
			return 1;
		}
	}
	fprintf(stderr, "Exiting AREQ API\n");
	return -1;
}
// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t
icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
  ptr += sizeof (icmphdr.icmp_type);
  chksumlen += sizeof (icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
  ptr += sizeof (icmphdr.icmp_code);
  chksumlen += sizeof (icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
  ptr += sizeof (icmphdr.icmp_id);
  chksumlen += sizeof (icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
  ptr += sizeof (icmphdr.icmp_seq);
  chksumlen += sizeof (icmphdr.icmp_seq);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Allocate memory for an array of chars.
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

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

