// from: http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastReceiver.c
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */

#define MAXRECVSTRING 255  /* Longest string to receive */
#define MAXLOGSIZE 2

int commandSize = 0;    //record the size of the cmdArray
/*
    This is a structure that represents a single unit of the og.
*/
struct logUnit{
    char* command;
    char* filename;
    char* time;
    char* content;   /*This will be empty for the remove command*/
};

/*
This function splits the command by whitespace and return them as an array
*/
char** checkStr(char* command){
    char** rst = (char**)malloc(1024*sizeof(char*));
    char *p = strtok(command, " ");
    int i = 0;
    while (p != NULL)
    {
        rst[i++] = p;
        p = strtok (NULL, " ");
    }
    commandSize = i;
    return rst;
}

int main(int argc, char *argv[])
{
    int sock;                         /* Socket */
    struct sockaddr_in broadcastAddr; /* Broadcast Address */
    unsigned short broadcastPort;     /* Port */
    char* recvString = (char*)calloc(1024, sizeof(char)); /* Buffer for received string */
    int recvStringLen;                /* Length of received string */
    struct logUnit log[MAXLOGSIZE];           /*a log to keep track of the information to stay consistant with other nodes*/
    int logSize = 0;

    if (argc != 2)    /* Test for correct number of arguments */
    {
        fprintf(stderr,"Usage: %s <Broadcast Port>\n", argv[0]);
        exit(1);
    }

    broadcastPort = atoi(argv[1]);   /* First arg: broadcast port */

    /* Create a best-effort datagram socket using UDP */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        perror("socket() failed");

    /* Construct bind structure */
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));   /* Zero out structure */
    broadcastAddr.sin_family = AF_INET;                 /* Internet address family */
    broadcastAddr.sin_addr.s_addr = htonl(INADDR_ANY);  /* Any incoming interface */
    broadcastAddr.sin_port = htons(broadcastPort);      /* Broadcast port */

    /* Bind to the broadcast port */
    if (bind(sock, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr)) < 0)
        perror("bind() failed");
    while(1){
        /* Receive a single datagram from the server */
        if ((recvStringLen = recvfrom(sock, recvString, MAXRECVSTRING, 0, NULL, 0)) < 0)
            perror("recvfrom() failed");

        recvString[recvStringLen] = '\0';
        printf("Received: %s\n", recvString);    /* Print the received string */

        /*Create user log to guarantee data consistency*/
        struct logUnit lu;
        char** cmdArray = checkStr(recvString);
        lu.command = (char*)calloc(4, sizeof(char));
        lu.filename = (char*)calloc(1024, sizeof(char));
        lu.time = (char*)calloc(22, sizeof(char));
        strcpy((lu.command), cmdArray[0]);
        strcpy((lu.filename), cmdArray[1]);
        strcpy((lu.time), cmdArray[2]);
        for(int i = 3; i < 7; ++i){
            strcat((lu.time), " ");
            strcat((lu.time), cmdArray[i]);
        }
        /* if the command is add, add the content to the log as well*/
        if(strcmp(lu.command, "add") == 0){
            int contentSize = commandSize - 7;
            lu.content = (char*)calloc(commandSize + 1, sizeof(char));
            strcpy((lu.content), cmdArray[7]);
            for(int i = 8; i < commandSize; ++i){
                strcat(lu.content, " ");
                strcat(lu.content, cmdArray[i]);
            }
        }

        /*The log only keeps track of MAXLOGSIZE most recent logs*/
        if(logSize == MAXLOGSIZE){
            for(int i = 0; i < MAXLOGSIZE - 1; ++i){
                log[i] = log[i + 1];
            }
            log[MAXLOGSIZE - 1] = lu;
            printf("%s\n", log[MAXLOGSIZE - 1].filename);
        }
        else{
            log[logSize] = lu;
            logSize++;
        }
    }
    close(sock);
    exit(0);
}