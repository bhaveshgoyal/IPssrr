#include	"hw_addrs.h"
#include "unp.h"
#include    <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>
#define BUFSIZE 1500
#define IPROTO_ICMP 1
// Define some constants.

char lo_ip[50];
uint8_t src_mac[6];
int ifidx = 0;
char nexthop_ip[50];
char prev_ip[20];
char tour[50];
char iface[20];
int datalen = 56;
proto *protc;
proto *rt_proto;

pid_t pid;
uint8_t nsent = 0;
int       rt;
char     sendbuf[BUFSIZE];

void process_rt(char *recvbuf);
void recv_rt();

int tour_recv = 0;
int lookup_loifaces(char *lo_ip, uint8_t *lo_mac, char *host);
int send_icmpp(char *srcip, uint8_t *srcmac, int ifidx, char *dsthost);

uint8_t *allocate_ustrmem (int len);
char *allocate_strmem (int len);

void sig_alrm(int signo)
{
 //   (*pr->fsend)();//
 	fprintf(stdout, "Sending ICMP");
	fflush(stdout);
    send_icmpp(lo_ip, src_mac, ifidx, prev_ip);
    alarm(10);
    return;
}

void process(char *ptr, ssize_t len, struct msghdr *msg){

    struct ip *ip;
    int hlen, icmplen;
    struct icmp      *icmp;
    
    ip = (struct ip*) ptr;

    hlen = ip->ip_hl << 2;

    if (ip->ip_p != IPROTO_ICMP)
        return;

    icmp = (struct icmp *) (ptr + hlen);

     if ( (icmplen = len - hlen) < 8){
        fprintf(stdout, "Malformed packet");
        fflush(stdout);
         return;            
     }/* malformed packet */

     if (icmp->icmp_type == ICMP_ECHOREPLY) {
         if (icmp->icmp_id != pid)
             return;                /* not a response to our ECHO_REQUEST */
         if (icmplen < 16)
             return;                /* not enough data to use */

         printf ("%d bytes from %s: seq=%u, ttl=%d\n",
                 icmplen, Sock_ntop_host (protc->sarecv, protc->salen),
                 icmp->icmp_seq, ip->ip_ttl);
     } 

}
void read_loop(){

    rt = Socket(protc->sasend->sa_family, SOCK_RAW, 1);
    struct iovec    iov;
    struct msghdr msg;
    char            recvbuf[BUFSIZE];
    char            controlbuf[BUFSIZE];
    ssize_t         n;

    if (setuid(getuid()) < 0){
        perror("Could nto set uid");
        return;
    }
    int size = 60 * 1024;

    setsockopt(rt, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    sig_alrm(SIGALRM);


    iov.iov_base = recvbuf;
    iov.iov_len = sizeof(recvbuf);
    msg.msg_name = protc->sarecv;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = controlbuf;

    while(1){
        msg.msg_namelen = protc->salen;

        msg.msg_controllen = sizeof(controlbuf);

        n = recvmsg(rt, &msg, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            else
                err_sys("recvmsg error");
        }
        
        process(recvbuf, n, &msg);
    }

}
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}
void send_rt(){
    
    unsigned long saddr;
    int payload_size = sizeof(tour);
    int sent, sent_size;

    saddr = inet_addr(lo_ip);

    int sockfd = Socket(AF_INET, SOCK_RAW, pid);

    if (sockfd < 0)
        perror("Could not create socket");
    
    int on = 1;
    
    Setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on));

    int packet_size = sizeof (struct iphdr) + payload_size;
    char *packet = (char *) malloc (packet_size);

    memset (packet, 0, packet_size);
    
    struct iphdr *ip = (struct iphdr *) packet;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = 0;
    ip->id = rand ();
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = pid;
    ip->saddr = saddr;
    ip->daddr = inet_addr(nexthop_ip);
    //inet_addr("172.217.12.174");
    ip->check = 0;
//    ip->check = in_cksum ((uint16_t*) ip, sizeof (struct iphdr));

    printf("tour: %s", tour);
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ip->daddr;
    memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

    memcpy(packet + sizeof(struct iphdr), tour, payload_size);

    Sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr));


}
void recv_rt(){
    
    int recvfd = Socket(AF_INET, SOCK_RAW, pid);
    char            recvbuf[BUFSIZE];
    ssize_t         n;
    struct sockaddr servaddr;
    int saddr_len = sizeof (servaddr);
     
	struct sockaddr from;
    socklen_t fromlen;
	uint8_t *recv_ether_frame;
	struct icmp *recv_icmphdr;
	struct ip *recv_iphdr;
	char *rec_ip;
	int bytes, recvsd;

    int size = 60 * 1024;
	setsockopt(recvfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	rec_ip = allocate_strmem (INET_ADDRSTRLEN);
	recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);
	
	if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
			perror ("socket() failed to obtain a receive socket descriptor ");
			exit (EXIT_FAILURE);
	}
	recv_iphdr = (struct ip *) (recv_ether_frame + ETH_HDRLEN);
	recv_icmphdr = (struct icmp *) (recv_ether_frame + ETH_HDRLEN + IP4_HDRLEN);

	memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
	memset (&from, 0, sizeof (from));
	fromlen = sizeof (from);


	fd_set readfs;
	FD_SET(recvfd, &readfs);
	FD_SET(recvsd, &readfs);
	int maxfd = -1;

	sigset_t sigset, oldset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, &oldset);

	while(1){
			FD_ZERO(&readfs);

			FD_SET(recvfd, &readfs);
//			if (tour_recv == 1){
					FD_SET(recvsd, &readfs);
					maxfd = max(recvfd, recvsd);
//			}
//			else
//					maxfd = recvfd;
//			fprintf(stdout, "Waiting on select");
//			fflush(stdout);
			int status = pselect(maxfd+1, &readfs, NULL, NULL, NULL, &oldset);

			if (status < 0){
					continue;
			}
			if (FD_ISSET(recvfd, &readfs)){
					Recvfrom(recvfd, recvbuf, sizeof(recvbuf),0, &servaddr, (socklen_t *)&saddr_len);
					struct iphdr *recvip = (struct iphdr*)recvbuf;
					inet_ntop(AF_INET, &(recvip->saddr), prev_ip, INET_ADDRSTRLEN);
					fprintf(stdout, "Tour received %s %s\n", recvbuf+sizeof(struct iphdr), prev_ip);
					process_rt((char *)(recvbuf+sizeof(struct iphdr)));
					if (tour_recv == 0){
						sig_alrm(SIGALRM);
						tour_recv = 1;
					}
			}
			else if (FD_ISSET(recvsd, &readfs)){
					if ((bytes = recvfrom (recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) < 0) {

							perror ("recvfrom() failed ");
							exit (EXIT_FAILURE);
					}  // End of error handling conditionals.

					if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IP) &&
									(recv_iphdr->ip_p == IPPROTO_ICMP) && (recv_icmphdr->icmp_id == (pid & 0xffff)) && (recv_icmphdr->icmp_type == ICMP_ECHOREPLY) && (recv_icmphdr->icmp_code == 0)) {

							if (inet_ntop (AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
									status = errno;
									fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
									exit (EXIT_FAILURE);
							}
							if (strcmp(rec_ip, lo_ip) == 0)
								continue;
							fprintf (stdout, "Reply from: %s (%i bytes received)\n", rec_ip, bytes);
							fflush(stdout);
					}
			}
	}
	close(recvsd);
	free(recv_ether_frame);
}
void process_rt(char *recvbuf){

    struct addrinfo *ai;
    
    char *tour_from = strtok(recvbuf, " ");

    char rem_tour[50] = {0};
    
    char *rem = strtok(NULL, "\n");
    
	if (!rem){
		fprintf(stderr, "End of Tour, Broadcast Now\n");
		//Broadcast now;
		while(1);
	}
    
	strcpy(tour, rem);

    char *nn = strtok(rem, " ");
    
    lookup_loifaces(lo_ip, src_mac, nn);

    ai = Host_serv(nn, NULL, 0, 0);
    char *nn_ip = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
    strcpy(nexthop_ip, nn_ip);
    printf("Tour from %s,  next hop %s (%s): %d data bytes\n",
            tour_from, ai->ai_canonname ? ai->ai_canonname : nn,
            nn_ip, datalen);
    rt_proto->sasend = ai->ai_addr;
    rt_proto->sarecv = Calloc(1, ai->ai_addrlen);

    send_rt();
}
int main(int argc, char **argv){
    int c;
    struct addrinfo *ai;
    char *h, *host;
    pid = 157 & 0xffff;
	protc = (proto*) malloc(sizeof(proto));
	rt_proto = (proto*) malloc(sizeof(proto));

	memset(tour, 0, sizeof(tour));
	
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
	struct sigaction s;
	s.sa_handler = sig_alrm;
	sigemptyset(&s.sa_mask);
	s.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &s, NULL);
	
	if (argc > 1){
			host = argv[1];
			int i = 1;
			for(i = 1; i < argc; i++){
            if (i != 1)
                strcat(tour, " ");
           strcat(tour, argv[i]);
        }
        ai = Host_serv(host, NULL, 0, 0);
        h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
        strcpy(nexthop_ip, h);
        printf("Next Hop %s (%s): %d data bytes\n",
                ai->ai_canonname ? ai->ai_canonname : h,
                h, datalen);
        rt_proto->sasend = ai->ai_addr;
        rt_proto->sarecv = Calloc(1, ai->ai_addrlen);
		

        send_rt();

    }
    
	recv_rt(); 

    return 0;
}

