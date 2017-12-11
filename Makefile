
CC = gcc

#LIBS =  /home/bhavesh/Desktop/CSE533/hw3/HW3_code/libs/unpv13e/libunp.a
LIBS = /home/courses/cse533/Stevens/unpv13e_linux/libunp.a

FLAGS = -g -O2

#CFLAGS = ${FLAGS} -I/home/bhavesh/Desktop/CSE533/hw3/HW3_code/libs/unpv13e/lib

CFLAGS = ${FLAGS} -I/home/courses/cse533/Stevens/unpv13e_linux/lib

all: arp_recv arp arp_resp

#get_hw_addrs.o: get_hw_addrs.c
#	${CC} ${CFLAGS} -c get_hw_addrs.c

arp:
	${CC} ${CFLAGS} -c arp.c ifaces.c icmputils.c get_hw_addrs.c
	${CC} ${CFLAGS} -o arp arp.o icmputils.o get_hw_addrs.o ifaces.o ${LIBS}

arp_recv:
	${CC} ${CFLAGS} arp_recv.c ${LIBS} -o arp_recv

arp_resp:
	${CC} ${CFLAGS} arp_resp.c get_hw_addrs.c ${LIBS} -o arp_resp

icmp:
	${CC} ${CFLAGS} -c icmp.c ifaces.c icmputils.c get_hw_addrs.c
	${CC} ${CFLAGS} -o icmp icmp.o icmputils.o get_hw_addrs.o ifaces.o ${LIBS}

cicmp:
	rm *.o
	rm icmp

carp:
	rm *.o
	rm arp
#${CC} ${CFLAGS} ifaces.c icmp.c icmputils.c get_hw_addrs.c ${LIBS} -o icmp

clean:
	rm arp arp_recv arp_resp

