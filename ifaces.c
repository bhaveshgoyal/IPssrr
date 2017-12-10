#include "unp.h"
#include "hw_addrs.h"

char *P_IP = "172.24.28.162";

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

