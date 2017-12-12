#include "unp.h"
#include "hw_addrs.h"

char *P_IPsub = "130.245.156.2";
char P_IP[20] = {0};
int lookup_loifaces(char *lo_ip, uint8_t *lo_mac, char *host){

	// Should always be like vmX
	char host_num = ((host[2] - '0') % 10) + '0';

	strcat(P_IP, P_IPsub);
	strcat(P_IP, (char*)&host_num);
	P_IP[14] = '\0';
	struct hwa_info	*hwa, *hwahead;
	struct sockaddr	*sa;
	char   *ptr;
	int    i, prflag;

	printf("Host Machine IP: %s\n", P_IP);

	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
			struct sockaddr *hwi = hwa->ip_addr;

			if ( (sa = hwa->ip_addr) != NULL && strcmp(Sock_ntop_host(sa, sizeof(*sa)), P_IP) == 0){
					printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
					
					printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));
					strcpy(lo_ip, Sock_ntop_host(sa, sizeof(*sa)));

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

int lookup_arploifaces(char *lo_ip, uint8_t *lo_mac, char *host){

	// Should always be like vmX
	char host_num = ((host[2] - '0') % 10) + '0';

	strcat(P_IP, P_IPsub);
	strcat(P_IP, (char*)&host_num);
	P_IP[14] = '\0';
	struct hwa_info	*hwa, *hwahead;
	struct sockaddr	*sa;
	char   *ptr;
	int    i, prflag;

	printf("Host Machine IP: %s\n", P_IP);

	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
			struct sockaddr *hwi = hwa->ip_addr;

			if ( (sa = hwa->ip_addr) != NULL && strcmp(Sock_ntop_host(sa, sizeof(*sa)), P_IP) == 0){
					printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
					
					printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));
					strcpy(lo_ip, Sock_ntop_host(sa, sizeof(*sa)));

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

