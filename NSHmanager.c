#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>

#define SENDPORT 6000
#define RECVPORT 6001
#define NSHMNG_Ctl_ip "10.0.5.3"
#define NSHMNG_IP "10.0.4.2"
#define SF1_IP    "10.0.4.8"
#define SF2_IP    "10.0.4.7"
#define F_PATH "SF_stats"
#define HOST_NUM 2 // according to the implementation,now we have two hosts

char cluster[2][2][100]={"iplab-Standard-PC-i440FX-PIIX-1996","10.0.4.8",
                         "iplab-Standard-PC-i440FX-PIIX-1997","10.0.4.7"};
struct 	SFCOrder{	//message from NSHcontroller
        int  SFCid;
        int  SFCNumber;
        int  SFClist[10];
};

struct 	OVSOrder{	//message sendto NSHagent
        int  SFtype;//0:NULL;1:CF;2:Firewall;3:NAT;4:IDS
        int  SFClength;
        int  SPI;
        int  SI;
        int  Encap;//0:NULL;1:vxlan
        char Remote[20];//0:NULL;1:Local;
        char *SFFip;//send this struct to which SFF
};

struct 	SFClist{		//chainlist of SF
        struct OVSOrder ovsorder;
        struct SFClist* pNext;
};

//SF instance struct, name,cpu(%),mem uage/limit and %, net I/O(KB). 
struct SF_ins {
    char host[200];
    char name[200];// host and container name
    double cpu; // 50% -> 50
    double mem; //KB;
    double mem_limit; //GB;
    double mem_per; //50% -> 50
    double net_i; //KB
    double net_o; //KB
};

struct SF_ins ins[1000];

//struct SF_ins *sf;
//sf=(struct sf *)malloc(sizeof(struct SF_ins));

struct 	SFCOrder recive();
void 	ordersend(struct OVSOrder order, char *ip);
int     ACKrecv(int start);
char 	*continer_search(int type);

struct 	SFClist* Create(struct SFCOrder sfcorder, int ISPI){	
	struct OVSOrder sfcCF, sfcFW, sfcNAT, sfcIDS, sfcEND; //each struct saves different SF information
	char *containerip;

		sfcCF.SFtype = 1;
        	sfcCF.SFClength = sfcorder.SFCNumber;
               	//sfcCF.SPI =sfcorder.SFCid;
		sfcCF.SPI = ISPI;
                sfcCF.SI = 4;
                sfcCF.Encap = 0;
		strcpy(sfcCF.Remote, "0.0.0.0");
		sfcCF.SFFip = SF1_IP;

		sfcFW.SFtype = 2;
                sfcFW.SFClength = sfcorder.SFCNumber;
                //sfcFW.SPI =sfcorder.SFCid;
		sfcFW.SPI = ISPI;
                sfcFW.SI = 3;
                sfcFW.Encap = 1;
                strcpy(sfcFW.Remote, "0.0.0.0");
		containerip = continer_search(2);
		printf("2containerip: %s\n",containerip);
		//sfcFW.SFFip = continer_search(2);
                sfcFW.SFFip = SF1_IP;
		
		sfcNAT.SFtype = 3;
                sfcNAT.SFClength = sfcorder.SFCNumber;
                //sfcNAT.SPI =sfcorder.SFCid;
		sfcNAT.SPI = ISPI;
                sfcNAT.SI = 2;
                sfcNAT.Encap = 1;
                strcpy(sfcNAT.Remote, "0.0.0.0");
		containerip = continer_search(3);
		printf("3containerip: %s\n",containerip);
                sfcNAT.SFFip = SF1_IP;

		sfcIDS.SFtype = 4;
                sfcIDS.SFClength = sfcorder.SFCNumber;
                //sfcIDS.SPI =sfcorder.SFCid;
		sfcIDS.SPI = ISPI;
                sfcIDS.SI = 1;
                sfcIDS.Encap = 1;
                strcpy(sfcIDS.Remote, "0.0.0.0");
		containerip = continer_search(4);
		printf("4containerip: %s\n",containerip);
                sfcIDS.SFFip = SF1_IP;

		sfcEND.SFtype = 0;
                sfcEND.SFClength = sfcorder.SFCNumber;
                sfcEND.SPI =sfcorder.SFCid;
                sfcEND.SI = 0;
                sfcEND.Encap = 0;
                strcpy(sfcEND.Remote, "0.0.0.0");
                sfcEND.SFFip = "0.0.0.0";

	
	struct SFClist* pHead = NULL;	//initailize SFClist chain
        struct SFClist* pEnd, *pNew;
	int i = 0;
	pEnd =  pNew = (struct SFClist*)malloc(sizeof(struct SFClist));
	pNew -> ovsorder = sfcCF;	//default set: the first SF is always ClassiFier(CF)
	printf("SFC length is %d and the list is following:\n",sfcorder.SFCNumber);
	printf("1  CF\n");
	while(i < sfcorder.SFCNumber){		
		i++;
		if(i == 1){
			pNew  -> pNext = pHead;
			pEnd  = pNew;
			pHead = pNew;
		}
		else{
			pNew -> pNext = NULL;
			pEnd -> pNext = pNew;
			pEnd = pNew;			
		}
		
		switch(sfcorder.SFClist[i]){
		case 0:
                        pNew = (struct SFClist*)malloc(sizeof(struct SFClist));
                        pNew->ovsorder = sfcEND;
                        //printf("%d  END\n",i+1);
                        break;
		case 1:
			pNew = (struct SFClist*)malloc(sizeof(struct SFClist));
                        pNew->ovsorder = sfcCF;	
			printf("%d  CF\n",i+1);
			break;
		case 2:
			pNew = (struct SFClist*)malloc(sizeof(struct SFClist));	
			pNew->ovsorder = sfcFW;		
			printf("%d  FW\n",i+1);
			break;
		case 3:
			pNew = (struct SFClist*)malloc(sizeof(struct SFClist));
                        pNew->ovsorder = sfcNAT;
			printf("%d  NAT\n",i+1);
			break;
		case 4:
			pNew = (struct SFClist*)malloc(sizeof(struct SFClist));
                        pNew->ovsorder = sfcIDS;
			printf("%d  IDS\n",i+1);
			break;
		}

	}
	free(pNew);
	return pHead;
}

//input a service name
//output host name and SF instance name
char *continer_search (int type)
{
	char service[20];       
	switch(type){
	case 2:
        	strcpy(service, "FW");//input service types(NAT,FW,IDS...);
		break;
	case 3:
		strcpy(service, "NAT");//input service types(NAT,FW,IDS...);
		break;
	case 4:
		strcpy(service, "IDS");//input service types(NAT,FW,IDS...);
		break;
	}
        char instance[200]; //output servie instances name; 
        char host[200]; //output host ip;
        int length;
        char *hostip;
        length=Read_Store();//read from SF_stats, store in Stuct ins[]
        Policy_algorithm(length,service,&host,&instance);
        
        //printf("the ip is %s\n",cluster[0][0]);
        //printf("the ip of the host is:%s\n", host);//out put the host;
        //printf("the instance is: %s\n", instance);// out put the instance;
        //memset(service, 0, sizeof(service));
        //memset(instance, 0, sizeof(instance));
        //memset(host, 0, sizeof(host));
	hostip = host;
	printf("dasabi: %s\n",hostip);
        return hostip;
	memset(service, 0, sizeof(service));
        memset(instance, 0, sizeof(instance));
        memset(host, 0, sizeof(host));
}

//a simple example, decide which sf instance will be used.
//choose sf instances with least workload.
int Policy_algorithm (int length,char service[], char host[], char instance[])
{

        //printf("Request service %s\n",service);

        int i,j=0,k;
        double min_mem;
        for (i=0;i<=length;i++)
        {
                if (strncmp(ins[i].name,service,strlen(service))==0)//find service type 
                        {
                                //printf("find\n");
                                j++;
                                if (j==1)
                                {
                                        min_mem=ins[i].mem; //record the first instance
                                        k=i;
                                }
                                else if (ins[i].mem<min_mem)// compare
                                {
                                        min_mem=ins[i].mem;
                                        k=i; //recode the location of min
                                        //printf("k :%d\n",k);
                                }
                        }

        }
        strcpy(host,ins[k].host);
        strcpy(instance,ins[k].name);
        //printf("Algorithm end the instace is %s,",ins[k].name);
        //printf("the host is %s\n",ins[k].host);
        int n;
        for (n=0;n<HOST_NUM;n++)
        {
                if (strcmp(host,cluster[n][0])==0)
                        strcpy(host,cluster[n][1]);
        }

        //printf("Algorithm end the instace is %s,",instance);
        //printf("the host is %s\n",host);
        return 0;
}


int Read_Store()
{
    int i=0;
    char entry[1000];
    FILE *fp;
    if(NULL == (fp= fopen(F_PATH,"r")))
    {
      //printf("error\n");
      exit(1);
    }
    while(NULL != (fgets(entry,1000,fp)))
    {
        i++;
        if (i==1) continue;
        //printf("%s",entry);


        char cpu[200];
        char mem[200];
        char mem_limit[200];
        char mem_per[200];
        char net_i[200];
        char net_o[200];
        char *p[110];
        //char temp[100]="0";
        p[0]=entry;
        int j,k=0;
        for (j=0;j<=strlen(entry);j++)
        {
                if (k<=10 && entry[j]=='*')
                        {
                          k=k+1;
                          p[k]= &entry[j];
                        }
        }

        strncpy(ins[i-1].host,entry,strlen(entry)-strlen(p[1]));
        //printf("host:%s ",ins[i-1].host);

        strncpy(ins[i-1].name,p[1]+1,strlen(p[1])-strlen(p[2])-1);
        //printf("name:%s ",ins[i-1].name);

        strncpy(cpu,p[2]+1,strlen(p[2])-strlen(p[3])-1);
        ins[i-1].cpu=atof(cpu);
        //printf("cpu:%f ",ins[i-1].cpu);

        strncpy(mem,p[3]+1,strlen(p[3])-strlen(p[4])-1);
        double unit1=1;
        if (strncmp(p[4],"*kB",3)==0)
                unit1=1;
        else if (strncmp(p[4],"*B",2)==0)
                unit1=1/1024;
        else if (strncmp(p[4],"*MB",3)==0)
                unit1=1024;
        else if (strncmp(p[4],"*GB",3)==0)
                unit1=1024*1024;
        //else printf("error");
        ins[i-1].mem=atof(mem)*unit1;
        //printf("mem:%f ",ins[i-1].mem);

        strncpy(mem_limit,p[5]+1,strlen(p[5])-strlen(p[6])-1);
        ins[i-1].mem_limit=atof(mem_limit);
        //printf("mem_limit:%f ",ins[i-1].mem_limit);

        strncpy(mem_per,p[7]+1,strlen(p[7])-strlen(p[8])-1);
        ins[i-1].mem_per=atof(mem_per);
        //printf("men_per:%f ",ins[i-1].mem_per);

        strncpy(net_i,p[8]+1,strlen(p[8])-strlen(p[9])-1);
        double unit2=1;//KB
        if (strncmp(p[9],"*kB",3)==0)
                unit2=1;
        else if (strncmp(p[9],"*B",2)==0)
                unit2=1/1024;
        else if (strncmp(p[9],"*MB",3)==0)
                unit2=1024;
        else if (strncmp(p[9],"*GB",3)==0)
                unit2=1024*1024;
        //else printf("error");
        ins[i-1].net_i=atof(net_i)*unit2;
        //printf("net_i:%f ",ins[i-1].net_i);

        strncpy(net_o,p[10]+1,strlen(p[10])-strlen(p[11])-1);
        double unit3=1;//KB
        if (strncmp(p[11],"*kB",3)==0)
                unit3=1;
        else if (strncmp(p[11],"*B",2)==0)
                unit3=1.000/1024;
        else if (strncmp(p[11],"*MB",3)==0)
                unit3=1024;
        else if (strncmp(p[11],"*GB",3)==0)
                unit3=1024*1024;
        //else printf("error");
        ins[i-1].net_o=atof(net_o)*unit3;//printf("unit is %f\n", unit3);       
        //printf("net_o:%f \n",ins[i-1].net_o);

        memset(cpu, 0, sizeof(cpu));
        memset(mem, 0, sizeof(mem));
        memset(mem_limit, 0, sizeof(mem_limit));
        memset(mem_per, 0, sizeof(mem_per));
        memset(net_i, 0, sizeof(net_i));
        memset(net_o, 0, sizeof(net_o));
    }

    fclose(fp);
    return i-1;
}

struct 	SFCOrder recive(){       //recive setup port message from NSHmanager.
        struct SFCOrder order, *Order;
        Order = &order;

        int socket_recv;
        socket_recv = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in addrrecv;
        int sockaddr_len = sizeof(struct sockaddr_in);
        bzero(&addrrecv,sockaddr_len);
        addrrecv.sin_family = AF_INET;
        addrrecv.sin_addr.s_addr = inet_addr(NSHMNG_Ctl_ip);
        addrrecv.sin_port = htons(RECVPORT);
        bind(socket_recv,(struct sockaddr *)&addrrecv,sockaddr_len);
        recvfrom(socket_recv,(char*)Order,sizeof(order),0,(struct sockaddr *)&addrrecv,&sockaddr_len);
        close(socket_recv);
        return order;
}

void 	Send(struct SFClist* pHead){
	struct SFClist *pTemp;
	int index = 1;
	int start;
	
	pTemp = pHead;
	while(pTemp != NULL){
		ordersend(pTemp->ovsorder, pTemp->ovsorder.SFFip);
		start = clock();
		pTemp = pTemp->pNext;
		index++;
		if(ACKrecv(start) == 1 ){
			printf("Start send openflow\n");
			printf("\n");
		}
		else{
			printf("SF setup failed\n");
			printf("\n");
			continue;
		}
	}
}

int     ACKrecv(int start){      //recive ACKmessage from NSHagnet.
        char recvBUF[25];
        int socket_recv;
        socket_recv = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in addrrecv;
        int sockaddr_len = sizeof(struct sockaddr_in);
        bzero(&addrrecv,sockaddr_len);
        addrrecv.sin_family = AF_INET;
        addrrecv.sin_addr.s_addr = inet_addr(NSHMNG_IP);
        addrrecv.sin_port = htons(RECVPORT);
        bind(socket_recv,(struct sockaddr *)&addrrecv,sockaddr_len);
        recvfrom(socket_recv,recvBUF,sizeof(recvBUF),0,(struct sockaddr *)&addrrecv,&sockaddr_len);
        close(socket_recv);
        printf("%s\n",recvBUF);
	memset(recvBUF,25,0);
        return 1;
}

void	ordersend(struct OVSOrder order, char *ip){
        int socket_send;
        socket_send = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in addrsend;
        bzero(&addrsend,sizeof(addrsend));
        addrsend.sin_family=AF_INET;
        addrsend.sin_port=htons(SENDPORT);
        addrsend.sin_addr.s_addr=inet_addr(ip);
        sendto(socket_send,(char*)&order,sizeof(order),0,(struct sockaddr *)&addrsend,sizeof(addrsend));
        close(socket_send);
	printf("SEND OUT to: %s\n", ip);
	//printf("%d", sizeof(order));
	sleep(2);
}

int 	main(){
	int end = 0;
	int i = 0;
	while(!end){
		i++;
		struct SFCOrder sfcorder = recive();
        	//sfcorder.SFCid = 6;
        	//sfcorder.SFCNumber = 4;
        	//sfcorder.SFClist[1] = 2;
        	//sfcorder.SFClist[2] = 3;
        	//sfcorder.SFClist[3] = 4;
		//sfcorder.SFClist[4] = 0;
		//sfcorder.SFClist[5] = 0;
	
		struct SFClist* pHead;
		pHead = Create(sfcorder, i);
		Send(pHead);
		printf("%d\n",i);
		if(i == 3){
			i = 0;		
		}
		else
			continue;
	}
	return 0;
}
