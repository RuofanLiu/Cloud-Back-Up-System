// from: http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastReceiver.c
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXRECVSTRING 255  /* Longest string to receive */
#define MAXLOGSIZE 2
#define FIFO_NAME "shared_data"
#define KEY_SIZE 256

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
    char *p = strtok(command, " \n");
    int i = 0;
    while (p != NULL)
    {
        rst[i++] = p;
        p = strtok (NULL, " \n");
    }
    commandSize = i;
    return rst;
}

/*
    This function checks if the file exists in the current directory or not by calling fopen
    returns 0 if the file exist and 1 otherwise
*/
int checkExistence(char* filename){
    FILE* file;
    file = fopen(filename, "r");
    if(file == NULL){
        return 1;
    }
    return 0;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
		unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) {
	  perror("decryption failed");
  }

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
	  perror("decryption failed");
  }
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
	  perror("decryption failed");
  }
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
	  perror("decryption failed");
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

char* receive_encrypted_msg(int sock, unsigned char* key) {
	char* iv_str = calloc(128, sizeof(char));
	int num;
	if ((num = recvfrom(sock, iv_str, 128, 0, NULL, 0)) < 0)
		perror("recvfrom() failed");

	char* encrypted_msg = calloc(1024, sizeof(char));
	if ((num = recvfrom(sock, encrypted_msg, 1024, 0, NULL, 0)) < 0)
		perror("recvfrom() failed");
    printf("Received encrypted msg: %s\n", encrypted_msg);    /* Print the received string */

	unsigned char* decrypted_msg = (unsigned char*)calloc(1024, sizeof(char));
	decrypt(encrypted_msg, strlen(encrypted_msg), key, iv_str, decrypted_msg);
	printf("decrypted as: %s", decrypted_msg);
	return decrypted_msg;
}

void generate_keys(int id, int sock, char* shared_secret_str) {
	char* recv_msg = (char*)calloc(KEY_SIZE+strlen("1 1 "), sizeof(char));
	char* round2_msg = (char*)calloc(KEY_SIZE, sizeof(char));
	int fd, num;
	// should receive a total of 6 messages from the servers
	for(int i = 0; i < 6; i++) {
        if ((num = recvfrom(sock, recv_msg, KEY_SIZE+strlen("1 1 "), 0, NULL, 0)) < 0)
            perror("recvfrom() failed");

        printf("Received: %s\n", recv_msg);    /* Print the received string */
		char** recv_msg_array = checkStr(recv_msg);
		if(atoi(recv_msg_array[0]) == (id + 2) % 3 && atoi(recv_msg_array[1]) == 1) {
			fd = open(FIFO_NAME, O_WRONLY);
			if ((num = write(fd, recv_msg_array[2], strlen(recv_msg_array[2]))) == -1)
				perror("write");
			else
				printf("sent round 1 message locally - %d bytes\n", num);
			close(fd);
		} else if(atoi(recv_msg_array[0]) == (id + 1) % 3 && atoi(recv_msg_array[1]) == 2) {
			strcpy(round2_msg, recv_msg_array[2]);
			printf("stored round2_msg: %s\n", round2_msg);
		}
	}
	// once all 6 messages have been received, we know for sure round 1 is over
	fd = open(FIFO_NAME, O_WRONLY);
	if (num = write(fd, round2_msg, strlen(round2_msg)) == -1)
		perror("write");
	else
		printf("sent round2 message locally - %d bytes\n", num);
	close(fd);

	// need to read symmetric key from server
	fd = open(FIFO_NAME, O_RDONLY);
	if ((num = read(fd, shared_secret_str, KEY_SIZE)) == -1)
            perror("read");
	else {
		printf("received shared secret - %d bytes: \"%s\"\n", num, shared_secret_str);
	}
	close(fd);
	unlink(FIFO_NAME);
}

int main(int argc, char *argv[])
{
    int sock;                         /* Socket */
    struct sockaddr_in broadcastAddr, Sender_addr; /* Broadcast Address */
    unsigned short broadcastPort;     /* Port */
    char* recvString = (char*)calloc(1024, sizeof(char)); /* Buffer for received string */
    int recvStringLen;                /* Length of received string */
    struct logUnit log[MAXLOGSIZE];           /*a log to keep track of the information to stay consistant with other nodes*/
    int logSize = 0;
	int id;
	char* shared_secret_str = (char*)calloc(KEY_SIZE, sizeof(char));

    if (argc != 3)    /* Test for correct number of arguments */
    {
        fprintf(stderr,"Usage: %s <Broadcast Port>\n", argv[0]);
        exit(1);
    }

    id = atoi(argv[1]);   /* First arg: node id*/
    broadcastPort = atoi(argv[2]);   /* First arg: broadcast port */

    /* Create a best-effort datagram socket using UDP */
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        perror("socket() failed");

    /* Construct bind structure */
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));   /* Zero out structure */
    broadcastAddr.sin_family = AF_INET;                 /* Internet address family */
    broadcastAddr.sin_addr.s_addr = htonl(INADDR_ANY);  /* Any incoming interface */
    broadcastAddr.sin_port = htons(broadcastPort);      /* Broadcast port */

    /* Bind to the broadcast port */
    if (bind(sock, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr)) < 0)
        perror("bind() failed");


	generate_keys(id, sock, shared_secret_str);
	receive_encrypted_msg(sock, shared_secret_str);

//    while(1) {
//        /* Receive a single datagram from the server */
//        if ((recvStringLen = recvfrom(sock, recvString, MAXRECVSTRING, 0, NULL, 0)) < 0)
//            perror("recvfrom() failed");
//
//        recvString[recvStringLen] = '\n';
//        printf("Received: %s\n", recvString);    /* Print the received string */
//	}

//    while(1){
//        /* Receive a single datagram from the server */
//        if ((recvStringLen = recvfrom(sock, recvString, MAXRECVSTRING, 0, NULL, 0)) < 0)
//            perror("recvfrom() failed");
//
//        recvString[recvStringLen] = '\n';
//        //printf("Received: %s\n", recvString);    /* Print the received string */
//
//        /*Create a local log for the server to read*/
//        FILE* fp;
//        fp = fopen("log.txt", "a+");
//        fputs(recvString, fp);
//        fclose(fp);
//
//        /*Create user log to guarantee data consistency*/
//        struct logUnit lu;
//        char** cmdArray = checkStr(recvString);
//        lu.command = (char*)calloc(4, sizeof(char));
//        lu.filename = (char*)calloc(1024, sizeof(char));
//        lu.time = (char*)calloc(22, sizeof(char));
//        strcpy((lu.command), cmdArray[0]);
//        strcpy((lu.filename), cmdArray[1]);
//        strcpy((lu.time), cmdArray[2]);
//        for(int i = 3; i < 7; ++i){
//            strcat((lu.time), " ");
//            strcat((lu.time), cmdArray[i]);
//        }
//        /* if the command is add, add the content to the log as well*/
//        if(strcmp(lu.command, "add") == 0){
//            int contentSize = commandSize - 7;
//            lu.content = (char*)calloc(commandSize + 1, sizeof(char));
//            strcpy((lu.content), cmdArray[7]);
//            for(int i = 8; i < commandSize; ++i){
//                strcat(lu.content, " ");
//                strcat(lu.content, cmdArray[i]);
//            }
//        }
//
//        /*The log only keeps track of MAXLOGSIZE most recent logs*/
//        if(logSize == MAXLOGSIZE){
//            for(int i = 0; i < MAXLOGSIZE - 1; ++i){
//                log[i] = log[i + 1];
//            }
//            log[MAXLOGSIZE - 1] = lu;
//        }
//        else{
//            log[logSize] = lu;
//            logSize++;
//        }
//
//        /*create or remove file baed on the command received from server*/
//        if(strcmp(lu.command, "add") == 0){
//            FILE* file;
//            file = fopen(lu.filename, "w+");
//            fputs(lu.content, file);   //write content to file
//            printf("%s added\n", lu.filename);
//            fclose(file);
//        }
//        else if(strcmp(lu.command, "rm") == 0){
//            if(checkExistence(lu.filename) == 0){
//                int status = remove(lu.filename);
//                if(status == 0){
//                    printf("%s deleted\n", lu.filename);
//                }
//            }
//            else{
//                printf("Target file does not exist\n");
//            }
//        }
//    }
    close(sock);
    exit(0);
}
