// from: http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastSender.c
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */

/*
	Supported Command:
	1. ADD <filename>
	2. REMOVE <filename>
*/

/*
This function checks if a string contains a valid command or not
It returns the substring before first whitespace
*/
char* checkStr(char* command){
	char *p = strtok(command, " ");
	if(!p){
		*p = 0;
	}
	return p;
}

int main(int argc, char *argv[])
{
    int sock;                         /* Socket */
    struct sockaddr_in broadcastAddr; /* Broadcast address */
    char *broadcastIP;                /* IP broadcast address */
    unsigned short broadcastPort;     /* Server port */
    char *sendString = (char*)malloc(1024*sizeof(char));                 /* String to broadcast */
    int broadcastPermission;          /* Socket opt to set permission to broadcast */
    unsigned int sendStringLen;       /* Length of string to broadcast */
	int number = 0;

    if (argc < 3)                     /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <IP Address> <Port> \n", argv[0]);
        exit(1);
    }

    broadcastIP = argv[1];            /* First arg:  broadcast IP address */ 
    broadcastPort = atoi(argv[2]);    /* Second arg:  broadcast port */
    //sendString = argv[3];             /* Third arg:  string to broadcast */	//TO DO: change the stringt be a message

    /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        perror("socket() failed");

    /* Set socket to allow broadcast */
    broadcastPermission = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (void *) &broadcastPermission, 
          sizeof(broadcastPermission)) < 0)
        perror("setsockopt() failed");

    /* Construct local address structure */
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));   /* Zero out structure */
    broadcastAddr.sin_family = AF_INET;                 /* Internet address family */
    broadcastAddr.sin_addr.s_addr = inet_addr(broadcastIP);/* Broadcast IP address */
    broadcastAddr.sin_port = htons(broadcastPort);         /* Broadcast port */

    
    printf("Starting UDP server for broadcasting\n");
    while(1) /* Run forever */
    {
    	/*take input command*/
    	printf("Type in a number \n");
		fgets(sendString, 1024, stdin);
		sendStringLen = strlen(sendString);  /* Find length of sendString */
		char* cmd = checkStr(sendString);
		if(strcmp(cmd, "ADD") == 0 || strcmp(cmd, "RM") == 0){
         /* Broadcast sendString in datagram to clients every 3 seconds*/
		
	        if (sendto(sock, sendString, sendStringLen, 0, (struct sockaddr *) 
	               &broadcastAddr, sizeof(broadcastAddr)) != sendStringLen){
	             perror("sendto() sent a different number of bytes than expected");
	     	}
	     	else{
	     		printf("Sending message to all clients: %s\n", sendString);
	     	}

	        sleep(3);   /* Avoids flooding the network */
     	}
    }
    /* NOT REACHED */
}

