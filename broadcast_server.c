// from: http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastSender.c
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <ctype.h>
#include <time.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h> /* openssl big numbers */
#include <openssl/rand.h> /* for generating random numbers */

#define FIFO_NAME "shared_data"

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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		perror("encryption failed");
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		perror("encryption failed");
	}

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		perror("encryption failed");
	}
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		perror("encryption failed");
	}
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

void send_encrypted_msg(int sock, struct sockaddr_in broadcastAddr, unsigned char* key, unsigned char* msg) {
	BIGNUM *iv = BN_new();
	BN_rand(iv, 512, -1, 0);
	unsigned char* iv_str = BN_bn2hex(iv);
	if (sendto(sock, iv_str, strlen(iv_str), 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != strlen(iv_str)){
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("Sending message to all clients: %s\n", iv_str);
	}
	char* encrypted_msg = (unsigned char*)calloc(1024, sizeof(char));
	encrypt(msg, strlen(msg), key, iv_str, encrypted_msg);
	if (sendto(sock, encrypted_msg, strlen(encrypted_msg), 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != strlen(encrypted_msg)){
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("Sending message to all clients: %s\n", iv_str);
	}
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
	char* id = (char*)malloc(16);
	RAND_poll();					  /* seed the RNG */

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *public_mod = BN_dup(BN_get_rfc2409_prime_1024(NULL));
	BIGNUM *public_base = BN_new();
	BIGNUM *private_key = BN_new();
	BIGNUM *public_key = BN_new();
	BIGNUM *intermediate_value = BN_new();
	BIGNUM *shared_secret = BN_new();
	BN_set_word(public_base, 2);
	BN_rand(private_key, 1024, -1, 0);

    if (argc < 4)                     /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <IP Address> <Port> \n", argv[0]);
        exit(1);
    }

	id = argv[1];
    broadcastIP = argv[2];            /* First arg:  broadcast IP address */ 
    broadcastPort = atoi(argv[3]);    /* Second arg:  broadcast port */

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

	/* key generation */
	/*
		round 1:
		A: send g^a to B (receive g^c)
		B: send g^b to C (receive g^a)
		C: send g^c to A (receive g^b)
		
		round 2:
		A: send g^ac to B (receive g^bc)
		B: send g^ab to C (receive g^ac)
		C: send g^bc to A (receive g^ab)
		
		then all can calculate g^abc
	* */
	BN_mod_exp(public_key, public_base, private_key, public_mod, ctx);

	char* public_key_str = BN_bn2hex(public_key);
	char* msgRound1 = (char*)malloc(strlen(public_key_str)+strlen(id)+strlen(" "));
	strcpy(msgRound1, id);
	strcat(msgRound1, " 1 ");
	strcat(msgRound1, public_key_str);

	if (sendto(sock, msgRound1, strlen(msgRound1), 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != strlen(msgRound1)){
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("Sending message to all clients: %s\n", msgRound1);

	}
	mknod(FIFO_NAME, S_IFIFO | 0644 , 0);

	int fd = open(FIFO_NAME, O_RDONLY);
	char* recvRound1 = (char*)calloc(256, sizeof(char));
	int num;
	if ((num = read(fd, recvRound1, 256)) == -1)
            perror("read");
        else {
            printf("tick: read %d bytes: \"%s\"\n", num, recvRound1);
    }

	// the following will compute g^ac, if we are at node A
	BIGNUM *recvRound1BN = BN_new();
	BN_hex2bn(&recvRound1BN, recvRound1);
	BN_mod_exp(intermediate_value, recvRound1BN, private_key, public_mod, ctx);
	printf("intermediate value: %s\n", BN_bn2hex(intermediate_value));

	char* int_value_str = BN_bn2hex(intermediate_value);
	char* msgRound2 = (char*)malloc(strlen(int_value_str)+strlen(id)+strlen(" 2 "));
	strcpy(msgRound2, id);
	strcat(msgRound2, " 2 ");
	strcat(msgRound2, int_value_str);

	if (sendto(sock, msgRound2, strlen(msgRound2), 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != strlen(msgRound2)){
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("Sending message to all clients: %s\n", msgRound2);

	}

	fd = open(FIFO_NAME, O_RDONLY);
	char* recvRound2 = (char*)calloc(256, sizeof(char));
	if ((num = read(fd, recvRound2, 256)) == -1)
            perror("read");
        else {
            printf("tick: read %d bytes: \"%s\"\n", num, recvRound2);
    }

	BIGNUM *recvRound2BN = BN_new();
	BN_hex2bn(&recvRound2BN, recvRound2);
	BN_mod_exp(shared_secret, recvRound2BN, private_key, public_mod, ctx);
	printf("shared secret: %s\n", BN_bn2hex(shared_secret));

	// send symmetric key to client on this same node
	fd = open(FIFO_NAME, O_WRONLY);
	char* shared_secret_str = BN_bn2hex(shared_secret);
	if (num = write(fd, shared_secret_str, strlen(shared_secret_str)) == -1)
		perror("write");
	else
		printf("speak: wrote %d bytes\n", num);

	send_encrypted_msg(sock, broadcastAddr, shared_secret_str, "test");

//    while(1) /* Run forever */
//    {
//    	/*take input command*/
//    	printf("Type in a valid command (add/rm <filename>) \n");
//		fgets(sendString, 1024, stdin);
//		char* command = (char*)malloc(1024*sizeof(char));
//		strcpy(command, sendString);
//		command[strlen(command) - 1] = 0;
//		char** cmdArray = checkStr(sendString);
//		if((strcmp(toLowerCase(cmdArray[0]), "add") == 0 && cmdArray[1] != NULL && cmdArray[1] != "\n")|| 
//			(strcmp(toLowerCase(cmdArray[0]), "rm") == 0 && cmdArray[1] != NULL && cmdArray[1] != "\n")){
//         /* Broadcast sendString in datagram to clients every 3 seconds*/
//			/*i the command is "add", retrieve the content and write to file*/
//			char* msgToSend = (char*)calloc(1024, sizeof(char));
//			char* timeStamp = (char*)calloc(1024, sizeof(char));
//			/*
//				The message to be sent will have the following format
//				<command> <filename> <timestamp> (<content>)
//			*/
//			sprintf(timeStamp, "%-24.24s", ctime(&t));
//			strcat(msgToSend, command);
//			strcat(msgToSend, " ");
//			strcat(msgToSend, timeStamp);
//
//			cmdArray[1][strlen(cmdArray[1]) - 1] = 0;	//remove the newline character caused by fgets
//			if(strcmp(toLowerCase(cmdArray[0]), "add") == 0){
//				printf("Please enter the content of the file\n");
//				char* content = (char*)malloc(1024*sizeof(char));
//				fgets(content, 1024, stdin);
//				content[strlen(content) - 1] = 0;	//remove the newline character in the content
//				strcat(msgToSend, " ");
//				strcat(msgToSend, content);
//			}
//
//			sendStringLen = strlen(msgToSend);
//			msgToSend[sendStringLen] = 0;
//
//
//	        if (sendto(sock, msgToSend, sendStringLen, 0, (struct sockaddr *) 
//	               &broadcastAddr, sizeof(broadcastAddr)) != sendStringLen){
//	             perror("sendto() sent a different number of bytes than expected");
//	     	}
//	     	else{
//	     		printf("Sending message to all clients: %s\n", msgToSend);
//	     	}
//
//	        sleep(1);   /* Avoids flooding the network */
//     	}
//     	else{
//     		printf("Command not found.\nUsage: add/rm <filename>\n");
//     	}
//    }
    /* NOT REACHED */
}
