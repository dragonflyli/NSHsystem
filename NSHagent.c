#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <netdb.h>            	// struct addrinfo
#include <sys/types.h>        	// needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       	// needed for socket()
#include <netinet/in.h>       	// IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip.h>       	// IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      	// struct ip6_hdr
#include <netinet/icmp6.h>    	// struct icmp6_hdr and ICMP6_ECHO_REQUEST
#include <arpa/inet.h>        	// inet_pton() and inet_ntop()
#include <sys/ioctl.h>        	// macro ioctl is defined
#include <bits/ioctls.h>      	// defines values for argument "request" of ioctl.
#include <net/if.h>           	// struct ifreq
#include <linux/if_ether.h>   	// ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  	// struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <inttypes.h> 		// uint8_t 
#include <limits.h> 		// UINT_MAX 
#include <stdbool.h>
#include <time.h> 		// clock_gettime() 
#include <poll.h> 		// poll()
#include <sys/uio.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h> 		// getifaddrs and freeifaddrs
#include <errno.h>            	// errno, perror()
#include <sys/times.h>		//times() fallback
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define RECVPORT 6000
#define SENDPORT 6001
#define NSHMNG_IP "10.0.4.2"
#define SF1_IP 	  "10.0.4.8"
#define SF2_IP    "10.0.4.7"
#define MAC_ADDR_LEN 18


struct OVSOrder{        //message sendto NSHagent
        int  SFtype;//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
        int  SFClength;
        int  SPI;
        int  SI;
        int  Encap;//0:NULL;1:vxlan
        char Remote[20];
        char *SFFip;
};

static struct OVSOrder recive();
static void Message_analysis();
static void nshport_starter(int nshportnumber, char *nshportname);
static void ovsbridge_starter(int bridgenumber, char *bridgename);
static void SPISI_builder(int SPInumber, int SInumber, int nshportnumber, char *nshportname, int encapnum, char *remoteip);
static void ACKsend(char *SFtype, char *MAC);
static void getEthMAC(unsigned char *macAddr, char *ifrName);
static char* getMAC(char *macaddress);

static  struct OVSOrder recive(){	//recive setup port message from NSHmanager.
	struct OVSOrder order, *Order;
        Order = &order;	

	int socket_recv;
	socket_recv = socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in addrrecv;
	int sockaddr_len = sizeof(struct sockaddr_in);
	bzero(&addrrecv,sockaddr_len);
	addrrecv.sin_family = AF_INET;
	addrrecv.sin_addr.s_addr = inet_addr(SF1_IP);
	addrrecv.sin_port = htons(RECVPORT);
	bind(socket_recv,(struct sockaddr *)&addrrecv,sockaddr_len);
	recvfrom(socket_recv,(char*)Order,sizeof(order),0,(struct sockaddr *)&addrrecv,&sockaddr_len);
	close(socket_recv);		
	return order;
}

static  void ACKsend(char *SFtype, char *MAC){	//return ACK message to NSHmanager.
	char ACKmsg[30] = "SF ";
        int socket_send;
        socket_send = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in addrsend;
        bzero(&addrsend,sizeof(addrsend));
        addrsend.sin_family=AF_INET;
        addrsend.sin_port=htons(SENDPORT);
        addrsend.sin_addr.s_addr=inet_addr(NSHMNG_IP);
	strcat(ACKmsg, SFtype);
	strcat(ACKmsg, " has establish!");
        sendto(socket_send,ACKmsg,strlen(ACKmsg),0,(struct sockaddr *)&addrsend,sizeof(addrsend));
        close(socket_send);
        printf("Send ACKmessage to NSHmanager: %s\n", NSHMNG_IP);
	memset(ACKmsg, 30, 0);
}

static  void getEthMAC(unsigned char *macAddr, char *ifrName){	//get MAC address of new port
        struct ifreq ifreq;
        int sock;
        if((sock=socket(AF_INET,SOCK_STREAM,0))<0)
        {       
                perror(" getEthMAC socket failed");
        }
        strcpy(ifreq.ifr_name,ifrName);
        //printf("ifrName = %s,ifreq.ifr_name = %s\n",ifrName,ifreq.ifr_name);
        if(ioctl(sock,SIOCGIFHWADDR,&ifreq)<0)
        {       
                perror(" getEthMAC ioctl failed");
        }
        memcpy(macAddr,(unsigned char *)ifreq.ifr_hwaddr.sa_data, sizeof(unsigned char)*6);

}

static  char* getMAC(char *macaddress){
	//char    Eth[10] = "";
        unsigned char    ETHMAC[6] = {0};
        int     opt;
	getEthMAC(ETHMAC, macaddress);
        char macAddrTmp[MAC_ADDR_LEN];
        snprintf(macAddrTmp, MAC_ADDR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
        ETHMAC[0],
        ETHMAC[1],
        ETHMAC[2],
        ETHMAC[3],
        ETHMAC[4],
        ETHMAC[5]);
        printf("the interface eth0 Mac address is %s\n", macAddrTmp);
	char *mac = macAddrTmp;
	return mac;	
}

static  void Message_analysis(){		//turn setup port message into system order.
	int i,j;
	struct OVSOrder order = recive();	//recive order from nshmanager
	//system("/root/ovs.sh");

	switch(order.SFtype){	//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
	case 1:
		printf("\n");
		printf("This SF is CF\n");
		//printf("%d\n",order.SFtype);//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
        	//printf("%d\n",order.SFClength);
        	//printf("%d\n",order.SPI);
        	//printf("%d\n",order.SI);
        	//printf("%d\n",order.Encap);//0:NULL;1:vxlan
        	//printf("%s\n",order.Remote);
        	//printf("%d\n",order.SFFip);
        	//printf("\n");
		char *SFtype1 = "CF";
		char *Remoteip1 = order.Remote;
		ovsbridge_starter(1, SFtype1);
        	nshport_starter(1, SFtype1);
       	 	SPISI_builder(order.SPI, order.SI, 1, SFtype1, order.Encap, Remoteip1); 
		sleep(3);
		char *macaddress1 = "eth0";
		char *mac1 = getMAC(macaddress1);
		//printf("%s",mac);
		//printf("eth0 mac is: %s\n",mac1);
		ACKsend(SFtype1, mac1);
		break;
	case 2:
		printf("\n");
		printf("This SF is FW\n");
		//printf("%d\n",order.SFtype);//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
        	//printf("%d\n",order.SFClength);
        	//printf("%d\n",order.SPI);
        	//printf("%d\n",order.SI);
        	//printf("%d\n",order.Encap);//0:NULL;1:vxlan
        	//printf("%s\n",order.Remote);
        	//printf("%d\n",order.SFFip);
        	//printf("\n");
		char *SFtype2 = "FW";
		char *Remoteip2 = order.Remote;
		ovsbridge_starter(2, SFtype2);
		nshport_starter(2, SFtype2);
		SPISI_builder(order.SPI, order.SI, 2, SFtype2, order.Encap, Remoteip2);
		sleep(3);
		char *macaddress2 = "eth0";
                char *mac2 = getMAC(macaddress2);
                //printf("%s",mac);
                //printf("eth0 mac is: %s\n",mac2);
                ACKsend(SFtype2, mac2);
		break;
	case 3:
		printf("\n");
		printf("This SF is NAT\n");
		//printf("%d\n",order.SFtype);//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
        	//printf("%d\n",order.SFClength);
        	//printf("%d\n",order.SPI);
        	//printf("%d\n",order.SI);
        	//printf("%d\n",order.Encap);//0:NULL;1:vxlan
        	//printf("%s\n",order.Remote);
        	//printf("%d\n",order.SFFip);
        	//printf("\n");
		char *SFtype3 = "NAT";
		char *Remoteip3 = order.Remote;
                ovsbridge_starter(2, SFtype3);
		nshport_starter(2, SFtype3);
		SPISI_builder(order.SPI, order.SI, 2, SFtype3, order.Encap, Remoteip3);
		sleep(3);
		char *macaddress3 = "eth0";
                char *mac3 = getMAC(macaddress3);
                //printf("%s",mac);
                //printf("eth0 mac is: %s\n",mac3);
                ACKsend(SFtype3, mac3);
		break;
	case 4:
		printf("\n");
		printf("This SF is IDS\n");
		//printf("%d\n",order.SFtype);//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
        	//printf("%d\n",order.SFClength);
        	//printf("%d\n",order.SPI);
        	//printf("%d\n",order.SI);
        	//printf("%d\n",order.Encap);//0:NULL;1:vxlan
        	//printf("%s\n",order.Remote);
        	//printf("%d\n",order.SFFip);
        	//printf("\n");
		char *SFtype4 = "IDS";
		char *Remoteip4 = order.Remote;
                ovsbridge_starter(2, SFtype4);
		nshport_starter(2, SFtype4);
		SPISI_builder(order.SPI, order.SI, 2, SFtype4, order.Encap, Remoteip4);
		sleep(3);
		char *macaddress4 = "eth0";
                char *mac4 = getMAC(macaddress4);
                //printf("%s",mac);
                //printf("eth0 mac is: %s\n",mac4);
                ACKsend(SFtype4, mac4);
		break;
	}
}

static  void ovsbridge_starter(int bridgenumber, char *bridgename){	
	int i;
        struct OVSOrder order;
	for(i = 0;i < bridgenumber;i++){ 	//add new bridges
        	if(i == 0){
			char ovs_add_br[30] = "ovs-vsctl add-br BR-";
			strcat(ovs_add_br, bridgename);
        		strcat(ovs_add_br, "-in");
        		printf("%s\n",ovs_add_br);
        		//system(ovs_add_br);
		}
		else{
			char ovs_add_br[30] = "ovs-vsctl add-br BR-";
                        strcat(ovs_add_br, bridgename);
                        strcat(ovs_add_br,"-out");
                        printf("%s\n",ovs_add_br);
                        //system(ovs_add_br);
		}
        }

	for(i = 0;i < bridgenumber;i++){        //start up brigdes 
                char ovs_br_up[30] = "ifconfig BR-";
                strcat(ovs_br_up, bridgename);
                if(i == 0){
                        if(strcmp(bridgename, "CF") == 0){
                                strcat(ovs_br_up, "-in 10.0.2.2/24 up");
                        }
                        if(strcmp(bridgename, "FW") == 0){
                                strcat(ovs_br_up, "-in 10.1.2.1/24 up");
                        }
                        if(strcmp(bridgename, "NAT") == 0){
                                strcat(ovs_br_up, "-in 10.1.4.1/24 up");
                        }
                        if(strcmp(bridgename, "IDS") == 0){
                                strcat(ovs_br_up, "-in 10.1.6.1/24 up");
                        }
			printf("%s\n",ovs_br_up);	
                        //system(ovs_br_up);
                }
                else{
                        if(strcmp(bridgename, "FW") == 0){
                                strcat(ovs_br_up, "-out 10.1.3.1/24 up");
                        }
                        if(strcmp(bridgename, "NAT") == 0){
                                strcat(ovs_br_up, "-out 10.1.5.1/24 up");
                        }
                        if(strcmp(bridgename, "IDS") == 0){
                                strcat(ovs_br_up, "-out 10.1.7.1/24 up");
                        }
			printf("%s\n",ovs_br_up);
                        //system(ovs_br_up);
                }
        }


	for(i = 0;i < bridgenumber;i++){	//bind bridges and tt/eth port
		char ovs_bind_tt[50] = "ovs-vsctl add-port BR-";
                char ovs_eth_clear[50] = "ifconfig ";
		if(i == 0){
                        if(strcmp(bridgename, "CF") == 0){
				strcat(ovs_bind_tt, bridgename);
                                strcat(ovs_bind_tt, "-in eth1");
                                strcat(ovs_eth_clear, "eth1 0.0.0.0");
                                printf("%s\n",ovs_bind_tt);
                                printf("%s\n",ovs_eth_clear);
                                //system(ovs_bind_tt);
				//system(ovs_eth_clear);
                        }
                        else{
				strcat(ovs_bind_tt, bridgename);
                                strcat(ovs_bind_tt, "-in tt-");
                                strcat(ovs_bind_tt, bridgename);
                                strcat(ovs_bind_tt, "-in");
				strcat(ovs_eth_clear, "tt-");
                                strcat(ovs_eth_clear, bridgename);
                                strcat(ovs_eth_clear, "-in 0.0.0.0");
                                printf("%s\n",ovs_bind_tt);
                                printf("%s\n",ovs_eth_clear);
				//system(ovs_bind_tt);
                                //system(ovs_eth_clear);
                        }
                }
                else{
			strcat(ovs_bind_tt, bridgename);
                        strcat(ovs_bind_tt, "-out tt-");
                        strcat(ovs_bind_tt, bridgename);
                        strcat(ovs_bind_tt, "-out");
			strcat(ovs_eth_clear, "tt-");
                        strcat(ovs_eth_clear, bridgename);
                        strcat(ovs_eth_clear, "-out 0.0.0.0");
                        printf("%s\n",ovs_bind_tt);
                        printf("%s\n",ovs_eth_clear);
			//system(ovs_bind_tt);
                        //system(ovs_eth_clear);
                }
	}
	
	for(i = 0;i < bridgenumber;i++){        //bind ovs bridges to controller
                if(i == 0){
                        char bind_br_ctl[60] = "ovs-vsctl set-controller BR-";
                        strcat(bind_br_ctl, bridgename);
                        strcat(bind_br_ctl, "-in");
			strcat(bind_br_ctl," tcp:");
                	strcat(bind_br_ctl,"192.168.5.31");
                	strcat(bind_br_ctl,":");
                	strcat(bind_br_ctl,"6633");
                	printf("%s\n",bind_br_ctl);
                	//system(bind_br_ctl);
                }
                else{
                      	char bind_br_ctl[60] = "ovs-vsctl set-controller BR-";
                        strcat(bind_br_ctl, bridgename);
                        strcat(bind_br_ctl, "-out");
                        strcat(bind_br_ctl," tcp:");
                        strcat(bind_br_ctl,"192.168.5.31");
                        strcat(bind_br_ctl,":");
                        strcat(bind_br_ctl,"6633");
                        printf("%s\n",bind_br_ctl);
                        //system(bind_br_ctl); 
                }
        }
}

static  void nshport_starter(int nshportnumber, char *nshportname){
	int i;
	struct OVSOrder order;
	for(i = 0;i < nshportnumber;i++){        //add new nsh port and start up nsh port
                if(i == 0){
			char ovs_add_nsh[40] = "ip link add name nsh-";
                	char ovs_nsh_up[30] = "ifconfig nsh-";
                	strcat(ovs_add_nsh, nshportname);
                	strcat(ovs_nsh_up, nshportname);
                	strcat(ovs_add_nsh,"-in");
                	strcat(ovs_nsh_up,"-in");
                	strcat(ovs_add_nsh," type nsh");
                	strcat(ovs_nsh_up," up");
                	printf("%s\n",ovs_add_nsh);
                	printf("%s\n",ovs_nsh_up);
                	//system(ovs_add_nsh);
                	//system(ovs_nsh_up);
                }
                else{
			char ovs_add_nsh[40] = "ip link add name nsh-";
                        char ovs_nsh_up[30] = "ifconfig nsh-";
                        strcat(ovs_add_nsh, nshportname);
                        strcat(ovs_nsh_up, nshportname);
                        strcat(ovs_add_nsh,"-out");
                        strcat(ovs_nsh_up,"-out");
                        strcat(ovs_add_nsh," type nsh");
                        strcat(ovs_nsh_up," up");
                        printf("%s\n",ovs_add_nsh);
                        printf("%s\n",ovs_nsh_up);
                        //system(ovs_add_nsh);
                        //system(ovs_nsh_up);
                }
        }		

	for(i = 0;i < nshportnumber;i++){        //bind bridges and nsh port
                if(i == 0){
			char bind_br_nsh[50] = "ovs-vsctl add-port BR-";
                	strcat(bind_br_nsh, nshportname);
                	strcat(bind_br_nsh, "-in");
                	strcat(bind_br_nsh, " nsh-");
			strcat(bind_br_nsh, nshportname);
			strcat(bind_br_nsh, "-in");
                	printf("%s\n",bind_br_nsh);
                	//system(bind_br_nsh);
        	}
		else{
			char bind_br_nsh[50] = "ovs-vsctl add-port BR-";
                        strcat(bind_br_nsh, nshportname);
                        strcat(bind_br_nsh, "-out");
                        strcat(bind_br_nsh, " nsh-");
                        strcat(bind_br_nsh, nshportname);
                        strcat(bind_br_nsh, "-out");
                        printf("%s\n",bind_br_nsh);
                        //system(bind_br_nsh);
                }
        }

}

static  void SPISI_builder(int SPInumber, int SInumber, int nshportnumber, char *nshportname, int encapnum, char *remoteip){
	int i;
        struct OVSOrder order;
	char SPInum[2];
	char SInum[2];
	if(strcmp(remoteip, "0.0.0.0") == 0){
		for(i = 0;i < nshportnumber;i++){        //add new spi road
		        if(i == 0){
		                char nsh_set_spi[50] = "ip nsh set dev nsh-";
				strcat(nsh_set_spi, nshportname);
				if(strcmp(nshportname,"CF") == 0){
					strcat(nsh_set_spi, "-in spi ");
				}
				else{
					strcat(nsh_set_spi, "-out spi ");
				}
				sprintf(SPInum, "%d" , SPInumber);
		                strcat(nsh_set_spi, SPInum);
		                memset(SPInum, 0, 2);
		                strcat(nsh_set_spi, " si ");
		                sprintf(SInum, "%d" , SInumber-1);
				if(SInumber < 2){
					continue;
				}
				else{
		                	strcat(nsh_set_spi, SInum);
		                	memset(SInum, 0, 2);
					printf("%s\n",nsh_set_spi);
		                	//system(nsh_set_spi);
				}
		        }
		        else{
				char nsh_add_spi[50] = "ip nsh add spi ";
				sprintf(SPInum, "%d" , SPInumber);
		                strcat(nsh_add_spi, SPInum);
				memset(SPInum, 0, 2);
				strcat(nsh_add_spi, " si ");
				strcat(nsh_add_spi, SPInum);
				sprintf(SInum, "%d" , SInumber);
		                strcat(nsh_add_spi, SInum);
				memset(SInum, 0, 2);
				strcat(nsh_add_spi, " dev nsh-");
				strcat(nsh_add_spi, nshportname);	
				strcat(nsh_add_spi, "-in");
		                printf("%s\n",nsh_add_spi);
		                //system(nsh_add_spi);
		        }
		}
	}
	else{
		for(i = 0;i < nshportnumber;i++){        //add new spi road
		        if(i == 0){
		                char nsh_set_spi[50] = "ip nsh set dev nsh-";
				strcat(nsh_set_spi, nshportname);
				if(strcmp(nshportname,"CF") == 0){
					strcat(nsh_set_spi, "-in spi ");
				}
				else{
					strcat(nsh_set_spi, "-out spi ");
				}
				sprintf(SPInum, "%d" , SPInumber);
		                strcat(nsh_set_spi, SPInum);
		                memset(SPInum, 0, 2);
		                strcat(nsh_set_spi, " si ");
		                sprintf(SInum, "%d" , SInumber-1);
				if(SInumber < 2){
					continue;
				}
				else{
		                	strcat(nsh_set_spi, SInum);
		                	memset(SInum, 0, 2);
					printf("%s\n",nsh_set_spi);
		                	//system(nsh_set_spi);

				}
				char nsh_add_spi_remote[50] = "ip nsh add spi ";
                                sprintf(SPInum, "%d" , SPInumber);
                                strcat(nsh_add_spi_remote, SPInum);
                                memset(SPInum, 0, 2);
                                strcat(nsh_add_spi_remote, " si ");
                                strcat(nsh_add_spi_remote, SPInum);
                                sprintf(SInum, "%d" , SInumber-1);
				if(SInumber < 2){
					continue;
				}
				else{
                                	strcat(nsh_add_spi_remote, SInum);
                                	memset(SInum, 0, 2);
                                	strcat(nsh_add_spi_remote, " remote ");
                                	strcat(nsh_add_spi_remote, remoteip);
                                	if(encapnum == 1){
                                	        strcat(nsh_add_spi_remote, " encap vxlan");
                                	}
                                	else{
                                	        continue;
                                	}

                                	printf("%s\n",nsh_add_spi_remote);
                                	//system(nsh_add_spi_remote);
				}
		        }
		        else{
				char nsh_add_spi[50] = "ip nsh add spi ";
                                sprintf(SPInum, "%d" , SPInumber);
                                strcat(nsh_add_spi, SPInum);
                                memset(SPInum, 0, 2);
                                strcat(nsh_add_spi, " si ");
                                strcat(nsh_add_spi, SPInum);
                                sprintf(SInum, "%d" , SInumber);
                                strcat(nsh_add_spi, SInum);
                                memset(SInum, 0, 2);
                                strcat(nsh_add_spi, " dev nsh-");
                                strcat(nsh_add_spi, nshportname);
                                strcat(nsh_add_spi, "-in");
                                printf("%s\n",nsh_add_spi);
                                //system(nsh_add_spi);
		        }
		}
	}       
}

void 	main(){	
	int end = 0;
	while(!end){
	Message_analysis();
	}
}
