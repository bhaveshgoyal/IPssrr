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
char nexthop_ip[50];
char tour[50];
char iface[20];
int datalen = 56;
proto *protc;
proto *rt_proto;

pid_t pid;
uint8_t nsent = 0;
int       rt;
char     sendbuf[BUFSIZE];

int send_icmpp();
void process_rt(char *recvbuf);
void recv_rt();

void sig_alrm(int signo)
{
 //   (*pr->fsend)();//
    send_icmpp();
    alarm(1);
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

    recv_rt();

}
void recv_rt(){
    

    int recvfd = Socket(AF_INET, SOCK_RAW, pid);
    char            recvbuf[BUFSIZE];
    ssize_t         n;
    struct sockaddr servaddr;
    int saddr_len = sizeof (servaddr);
    
    int size = 60 * 1024;
    setsockopt(recvfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    while(1){
        Recvfrom(recvfd, recvbuf, sizeof(recvbuf),0, &servaddr, (socklen_t *)&saddr_len);
            fprintf(stdout, "%s", recvbuf+sizeof(struct iphdr));
            process_rt((char *)(recvbuf+sizeof(struct iphdr)));
    }


}
void process_rt(char *recvbuf){

    struct addrinfo *ai;
    
    strtok(recvbuf, " ");
    
    char rem_tour[50] = {0};
    
    char *rem = strtok(NULL, "\n");
    
    if (!rem){
        fprintf(stderr, "tour end");
        // BroadCase Now;
    }
    
    strcpy(tour, rem);

    lookup_loifaces(lo_ip, src_mac);
    char *nn = strtok(rem, " ");

    ai = Host_serv(nn, NULL, 0, 0);
    char *nn_ip = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
    strcpy(nexthop_ip, nn_ip);

    printf("PING %s (%s): %d data bytes\n",
            ai->ai_canonname ? ai->ai_canonname : nn,
            nn_ip, datalen);
    rt_proto->sasend = ai->ai_addr;
    rt_proto->sarecv = Calloc(1, ai->ai_addrlen);

    send_rt();
}
int main(int argc, char **argv){
    int c;
    struct addrinfo *ai;
    char *h, *host = "ENVY-BHAVESH";
    pid = 157 & 0xffff;
    protc = (proto*) malloc(sizeof(proto));
    rt_proto = (proto*) malloc(sizeof(proto));

    memset(tour, 0, sizeof(tour));
    if (argc > 1){
        int i = 1;
        for(i = 1; i < argc; i++){
            if (i != 1)
                strcat(tour, " ");
           strcat(tour, argv[i]);
        }
        ai = Host_serv(host, NULL, 0, 0);
        h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
        strcpy(nexthop_ip, h);
        printf("PING %s (%s): %d data bytes\n",
                ai->ai_canonname ? ai->ai_canonname : h,
                h, datalen);
        rt_proto->sasend = ai->ai_addr;
        rt_proto->sarecv = Calloc(1, ai->ai_addrlen);
        lookup_loifaces(lo_ip, src_mac);

        send_rt();
    //    read_loop();

    }
    else
        recv_rt(); 


//    Signal(SIGALRM, sig_alrm);
    

   

    return;
}

