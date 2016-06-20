/*
�������ò��裺
1���궨���޸�
//�������������������
#define PHYSICALPORT "eth0"	�����������ںš���������װ�豸����Ҫ�޸�Ϊǡ�����������ںţ�Ҫ����������ڵ������豸�У������ں�Ψһ
2��ϵͳ����
��Fedoraϵͳ������Ҫʹ��ԭʼ�׽��ַ����Զ����ʽ�����ݰ�����ر�Fedora�ķ���ǽ�����
sudo systemctl stop firewalld.service
��Ubuntuϵͳ�������κβ���
3����������
gcc physicalport_recv.c -o physicalport_recv
4�����У����漰ԭʼ�׽��ֵ�ʹ�ã���rootȨ�ޣ�
sudo ./physicalport_recv
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <resolv.h>
#include <signal.h>
#include <getopt.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*******************************************************************************************************************************************
*************************************�궨����������************ȫ�ֱ�������************����ʽ����*********************************************
*******************************************************************************************************************************************/
//�����˿ڣ����ں궨�����룩
#define PHYSICALPORT       "eth3"
#define PHYSICALPORTlength 5
#define SENDPORT 6666
#define ControllerIP "127.0.0.1"

//�����˿ڣ�ʵ�ʳ�����ʹ�ò�ʶ������壩
char PhysicalPort[6];

//���ͻ�������С
#define BUFFSIZE     1024 * 5

//���ջ�����
static int RecvBUFFSIZE = BUFFSIZE;
static char RecvBuf[BUFFSIZE] = {0};

//structure of metadata to NSHcontroller
struct  metadata{
	char protocol[2];	
	char src_ip[16];
	char dst_ip[16];	
};

void CFrequstsend(struct metadata meta);
/*****************************************
* �������ƣ�Ethernet_SetPromisc
* ����������������������ģʽ���Բ���
* �����б�const char *pcIfName, int fd, int iFlags
* ���ؽ����static int
*****************************************/
static int Ethernet_SetPromisc(const char *pcIfName,int fd,int iFlags)
{
	int iRet = -1;
	struct ifreq stIfr;
	
	//��ȡ�ӿ����Ա�־λ
	strcpy(stIfr.ifr_name,pcIfName);
	iRet = ioctl(fd,SIOCGIFFLAGS,&stIfr);
	if(0 > iRet)
	{
		perror("[Error]Get Interface Flags");   
		return -1;
	}
	
	if(0 == iFlags)
	{
		//ȡ������ģʽ
		stIfr.ifr_flags &= ~IFF_PROMISC;
	}
	else
	{
		//����Ϊ����ģʽ
		stIfr.ifr_flags |= IFF_PROMISC;
	}
	
	//���ýӿڱ�־
	iRet = ioctl(fd,SIOCSIFFLAGS,&stIfr);
	if(0 > iRet)
	{
		perror("[Error]Set Interface Flags");
		return -1;
	}
	
	return 0;
}

/*****************************************
* �������ƣ�Ethernet_InitSocket
* ��������������ԭʼ�׽���
* �����б�
* ���ؽ����static int
*****************************************/
static int Ethernet_InitSocket()
{
	int iRet = -1;
	int fd = -1;
	struct ifreq stIf;
	struct sockaddr_ll stLocal = {0};
	
	//����SOCKET
	fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	//fd = socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
	
	//��������ģʽ����
	Ethernet_SetPromisc(PhysicalPort,fd,1);
	
	//����SOCKETѡ��
	iRet = setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&RecvBUFFSIZE,sizeof(int));
	
	//��ȡ���������ӿ�����
	strcpy(stIf.ifr_name,PhysicalPort);
	iRet = ioctl(fd,SIOCGIFINDEX,&stIf);
	
	//����������
	stLocal.sll_family = PF_PACKET;
	stLocal.sll_ifindex = stIf.ifr_ifindex;
	stLocal.sll_protocol = htons(ETH_P_ALL);
	iRet = bind(fd,(struct sockaddr *)&stLocal,sizeof(stLocal));
	return fd;   
}

/*****************************************
* �������ƣ�Ethernet_StartCapture
* ����������������������֡
* �����б�const int fd
* ���ؽ����void
*****************************************/
static void Ethernet_StartCapture(const int fd){
	struct metadata meta;
  	unsigned char buff[BUFFSIZE];
	unsigned char dst_mac[18] = "";
	unsigned char src_mac[18] = "";
	unsigned char version[2]  = "";
	unsigned char Headlen[2]  = "";
	unsigned char totallen[2] = "";
	unsigned char ttl[2] = "";
	unsigned char protocol[2] = "";	
	unsigned char src_ip[16] = "";
	unsigned char dst_ip[16] = "";
  	int n;
  	int count = 0;

    while(1){  
    	n = recvfrom(fd,buff,BUFFSIZE,0,NULL,NULL);
    	if(n<0){
        	printf("receive error!\n");
        	exit(1);
    		}
         
    	count++;
    	struct ip *ip = (struct ip*)buff; 
 
    	int i=0,j=0;
    	for(i=0;i<n;i++){
        	if(i!=0 && i%16==0){
            	printf("    ");
            		for(j=i-16;j<i;j++){
                		if(buff[j]>=32&&buff[j]<=128)
                			printf("%c",buff[j]);
                		else printf(".");
            		}
        		printf("\n");
        	}
    		if(i%16 == 0) 
				printf("%04x  ",i);          
    			printf("%02x",buff[i]);
     
    		if(i==n-1){
        		for(j=0;j<15-i%16;j++) 
					printf("  ");
        			printf("    ");
        		for(j=i-i%16;j<=i;j++){
            		if(buff[j]>=32&&buff[j]<127)
                    	printf("%c",buff[j]);
                    else 
						printf("."); 
           		}
      		}
   		}
       
		printf("\n");
		sprintf(dst_mac,"%02x:%02x:%02x:%02x:%02x:%02x", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5]);    
        sprintf(src_mac,"%02x:%02x:%02x:%02x:%02x:%02x", buff[6], buff[7], buff[8], buff[9], buff[10], buff[11]);  
		sprintf(version,"%01d",buff[14]/16);
		sprintf(Headlen,"%02d",(buff[14]%16)*4); 
		sprintf(totallen,"%02d",buff[17]);
		sprintf(ttl,"%02d",buff[22]);
		sprintf(protocol, "%02d", buff[23]);
		sprintf(dst_ip,"%03d.%03d.%03d.%03d", buff[26], buff[27], buff[28], buff[29]);
		sprintf(src_ip,"%03d.%03d.%03d.%03d", buff[26], buff[27], buff[28], buff[29]);
		printf("Ethernet II:");
		printf(" Src:%s, Dst:%s\n",src_mac,dst_mac);
		printf("internet protocol\n");
		printf("version:%s\n",version);
		printf("Header Length:%s bytes\n",Headlen);
		printf("totle length:%s\n",totallen);
		printf("Time to live:%s\n",ttl);
		if(strcmp(protocol,"06")==0)
			printf("protocol TCP(6)\n");
		else if(strcmp(protocol,"01")==0)
			printf("protocol ICMP(1)\n");
		else if(strcmp(protocol,"17")==0)
			printf("protocol UDP(17)\n");
		printf("source ip:%s\n",src_ip);
		printf("destination ip:%s\n",dst_ip);
		strcpy(meta.protocol, protocol);
		strcpy(meta.src_ip, src_ip);
		strcpy(meta.dst_ip, dst_ip);
		CFrequstsend(meta);
		
         
		//TCP
		if(strcmp(protocol,"06")==0){
			printf("transmission control protocol\n");
			struct tcphdr *tcp=(struct tcphdr *)(buff+34); 
			printf("source port:%u\n",ntohs(tcp->source));
			printf("destation port:%u\n",ntohs(tcp->dest));
			//printf("sequence number:%u\n",ntohs(tcp->seq));
			//printf("acknowledgement number:%u\n",ntohs(tcp->ack_seq));
			//printf("head length:%d\n",ntohs((tcp->doff)*4));
			printf("window size:%u\n",ntohs(tcp->window));
		}
     
		//UDP
		if(strcmp(protocol,"17")==0){
			struct udphdr *udp=(struct udphdr*)(buff+34);
			printf("user datagram protocol\n");
			printf("source port:%u\n",udp->source);
			printf("destination port:%u\n",udp->dest);
			printf("length:%u\n",ntohs(udp->len));
		}

		//ICMP
		if(strcmp(protocol,"01")==0){
			struct icmphdr *icmp = (struct icmphdr *)(buff+34);
			printf("Internet Control Message Protocol\n");
			printf("type:%u",icmp->type);
			if(icmp->type==0)
				printf("(Echo Reply)\n");
			else if(icmp->type==8)
				printf("(Echo)\n");
			else if(icmp->type==5)
				printf("(Redirect)\n");
			else if(icmp->type==3)
				printf("(Dest Unreach)\n");
			else if(icmp->type==4)
				printf("(Source quench)\n");
			else if(icmp->type==13)
				printf("(Time Stamp)\n");
			else if(icmp->type==14)
				printf("(Time Stamp Reply)\n");
				printf("Code:%u\n",icmp->code);
			if(icmp->type==0||icmp->type==8){
				    printf("idetifier:0x%x\n",ntohs(icmp->un.echo.id));
				    printf("Sequence:%u\n",ntohs(icmp->un.echo.sequence));
				}
			if(icmp->type==3||icmp->type==4){
				    //printf("Unused:%u\n",ntohs(icmp->un.frag.unused));
				    printf("Mtu:%u\n",ntohs(icmp->un.frag.mtu));
				}  
			if(icmp->type==5)
				printf("Gateway:%u\n",ntohs(icmp->un.gateway));
		}    
    	printf("\n\n");
	}
}

/*****************************************
* �������ƣ�CFrequstsend
* ����������CF send message to NSHcontroller
* �����б�const int fd
* ���ؽ����void
*****************************************/
void CFrequstsend(struct metadata meta){
        int socket_send;
        socket_send = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in addrsend;
        bzero(&addrsend,sizeof(addrsend));
        addrsend.sin_family=AF_INET;
        addrsend.sin_port=htons(SENDPORT);
        addrsend.sin_addr.s_addr=inet_addr(ControllerIP);
        sendto(socket_send,(char*)&meta,sizeof(meta),0,(struct sockaddr *)&addrsend,sizeof(addrsend));
        close(socket_send);
}

/*****************************************
* �������ƣ�main
* ����������������
* �����б�
* ���ؽ����
*****************************************/
void main()
{
	memcpy(PhysicalPort,PHYSICALPORT,PHYSICALPORTlength);

	//��ʼ��SOCKET
	int fd   = -1;
	fd = Ethernet_InitSocket();
	if(0 > fd)
	{
		exit(0);
	}
	//�������ݰ�����ѭ����
	Ethernet_StartCapture(fd);
	
	//�ر�SOCKET
	close(fd);
}
