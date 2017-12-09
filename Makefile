
CC = gcc

LIBS =  /home/bhavesh/Desktop/CSE533/hw3/HW3_code/libs/unpv13e/libunp.a

FLAGS = -g -O2
CFLAGS = ${FLAGS} -I/home/bhavesh/Desktop/CSE533/hw3/HW3_code/libs/unpv13e/lib

all: arp_recv arp arp_resp

#get_hw_addrs.o: get_hw_addrs.c
#	${CC} ${CFLAGS} -c get_hw_addrs.c

arp:
	${CC} ${CFLAGS} arp.c get_hw_addrs.c ${LIBS} -o arp

arp_recv:
	${CC} ${CFLAGS} arp_recv.c ${LIBS} -o arp_recv

arp_resp:
	${CC} ${CFLAGS} arp_resp.c get_hw_addrs.c ${LIBS} -o arp_resp

clean:
	rm arp arp_recv arp_resp

