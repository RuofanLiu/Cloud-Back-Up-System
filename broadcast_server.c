// from: http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastSender.c
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <ctype.h>
#include <time.h>

/*
	Supported Command:
	1. ADD <filename>
	2. REMOVE <filename>
*/

/*
This function splits the command by whitespace and return them as an array
*/
char** checkStr(char* command){
	char** rst = (char**)malloc(2*sizeof(char*));
	char *p = strtok(command, " \n");
	int i = 0;
	while (p != NULL)
    {
        rst[i++] = p;
        p = strtok (NULL, "/");
    }
	return rst;
}

/*
	This fucntion returns the input string to lower case
*/
char* toLowerCase(char* str){
	for(int i = 0; str[i]; i++){
	  str[i] = tolower(str[i]);
	}
	return str;
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
	time_t t = time(0);

    if (argc < 3)                     /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <IP Address> <Port> \n", argv[0]);
        exit(1);
    }

    broadcastIP = argv[1];            /* First arg:  broadcast IP address */ 
    broadcastPort = atoi(argv[2]);    /* Second arg:  broadcast port */

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
    	here:
    	printf("Type in a valid command (add/rm <filename>) \n");
		fgets(sendString, 1024, stdin);
		char* command = (char*)malloc(1024*sizeof(char));
		strcpy(command, sendString);
		command[strlen(command) - 1] = 0;
		char** cmdArray = checkStr(sendString);
		if((strcmp(toLowerCase(cmdArray[0]), "add") == 0 && cmdArray[1] != NULL && cmdArray[1] != "\n")|| 
			(strcmp(toLowerCase(cmdArray[0]), "rm") == 0 && cmdArray[1] != NULL && cmdArray[1] != "\n")){
         /* Broadcast sendString in datagram to clients every 3 seconds*/
			/*i the command is "add", retrieve the content and write to file*/
			char* msgToSend = (char*)calloc(1024, sizeof(char));
			char* timeStamp = (char*)calloc(1024, sizeof(char));
			/*
				The message to be sent will have the following format
				<command> <filename> <timestamp> (<content>)
			*/
			sprintf(timeStamp, "%-24.24s", ctime(&t));
			strcat(msgToSend, command);
			strcat(msgToSend, " ");
			strcat(msgToSend, timeStamp);

			cmdArray[1][strlen(cmdArray[1]) - 1] = 0;	//remove the newline character caused by fgets
			if(strcmp(toLowerCase(cmdArray[0]), "add") == 0){
				printf("Please enter the content of the file\n");
				char* content = (char*)malloc(1024*sizeof(char));
				fgets(content, 1024, stdin);
				content[strlen(content) - 1] = 0;	//remove the newline character in the content
				strcat(msgToSend, " ");
				strcat(msgToSend, content);
			}

			sendStringLen = strlen(msgToSend);
			msgToSend[sendStringLen] = 0;


	        if (sendto(sock, msgToSend, sendStringLen, 0, (struct sockaddr *) 
	               &broadcastAddr, sizeof(broadcastAddr)) != sendStringLen){
	             perror("sendto() sent a different number of bytes than expected");
	     	}
	     	else{
	     		printf("Sending message to all clients: %s\n", msgToSend);
	     	}

	        sleep(1);   /* Avoids flooding the network */
     	}
     	else{
     		printf("Command not found.\nUsage: add/rm <filename>\n");
     		goto here;
     	}
    }
    /* NOT REACHED */
}