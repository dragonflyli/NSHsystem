#include<stdio.h>
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

#define SENDPORT 6001
#define RECVPORT 6000
#define NSHMNG_Ctl_ip "10.0.5.3"

struct  SFCOrder{       //message from NSHcontroller
        int  SFCid;
        int  SFCNumber;
        int  SFClist[10];
};

void    ordersend(struct SFCOrder order);

void    ordersend(struct SFCOrder order){
        int socket_send;
        socket_send = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in addrsend;
        bzero(&addrsend,sizeof(addrsend));
        addrsend.sin_family=AF_INET;
        addrsend.sin_port=htons(SENDPORT);
        addrsend.sin_addr.s_addr=inet_addr(NSHMNG_Ctl_ip);
        sendto(socket_send,(char*)&order,sizeof(order),0,(struct sockaddr *)&addrsend,sizeof(addrsend));
        close(socket_send);
        printf("SEND OUT to: %s\n", NSHMNG_Ctl_ip);
        //printf("%d", sizeof(order));
}

void main(){
	struct SFCOrder sfcorder;
	sfcorder.SFCid = 6;
        sfcorder.SFCNumber = 4;
        sfcorder.SFClist[1] = 2;
        sfcorder.SFClist[2] = 3;
        sfcorder.SFClist[3] = 4;
        sfcorder.SFClist[4] = 0;
	ordersend(sfcorder);
}
