// from: http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/code/BroadcastSender.c
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

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
#define MAX_CONTENT_LEN 2048
#define MAX_FILENAME_LEN 64
#define TIME_LEN 25
#define COMMAND_LEN 3
#define MAX_LOG_SIZE 2
#define KEY_LEN 256
#define IV_LEN 128
#define MAX_MSG_LEN MAX_CONTENT_LEN+MAX_FILENAME_LEN+TIME_LEN+COMMAND_LEN  /* Longest string to receive */

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
		perror("failed to create ctx");
	}

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		perror("encryption init failed");
	}

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		perror("encryption update failed");
	}
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		perror("encryption final failed");
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
		printf("Sending initialization vector: %s\n", iv_str);
	}
	char* encrypted_msg = (unsigned char*)calloc((strlen(msg)/128+1)*128, sizeof(char));

	struct timeval  tv1, tv2;
	gettimeofday(&tv1, NULL);

	int encrypted_msg_len = encrypt(msg, strlen(msg), key, iv_str, encrypted_msg);

	gettimeofday(&tv2, NULL);
	printf("Time taken to encrypt message: %f milliseconds\n", (double) (tv2.tv_sec - tv1.tv_sec) *1000000 + (double) (tv2.tv_usec - tv1.tv_usec));

	if (sendto(sock, encrypted_msg, encrypted_msg_len, 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != encrypted_msg_len) {
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("broadcasting encrypted message:\n");
		BIO_dump_fp(stdout, encrypted_msg, encrypted_msg_len);
	}
	BN_clear(iv);
}

/* The following procedure is used for key generation:
	round 1:
	A: send g^a to B (receive g^c)
	B: send g^b to C (receive g^a)
	C: send g^c to A (receive g^b)
	
	round 2:
	A: send g^ac to B (receive g^bc)
	B: send g^ab to C (receive g^ac)
	C: send g^bc to A (receive g^ab)
	
	then all can calculate g^abc
*/
void generate_keys(char* id_str, int sock, struct sockaddr_in broadcastAddr, BIGNUM* shared_secret) {
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *public_mod = BN_dup(BN_get_rfc2409_prime_1024(NULL)); // our "p" in diffie-hellman
	BIGNUM *private_key = BN_new();
	BIGNUM *public_key = BN_new();
	BIGNUM *intermediate_value = BN_new();

	BIGNUM *public_base = BN_new(); // our "g" in diffie-hellman
	BN_set_word(public_base, 2); //rfc 2409 uses 2 as the generator

	BN_rand(private_key, 1024, -1, 0); // our private key is a random 1024-bit integer

	// calculate the public key as g^(priv) mod p
	BN_mod_exp(public_key, public_base, private_key, public_mod, ctx);

	// construct the message to broadcast: <id 1 public_key> (1 to denote round 1 of communication)
	char* public_key_str = BN_bn2hex(public_key);
	char* round1_msg = (char*)malloc(KEY_LEN+strlen(id_str)+strlen(" 1 ")+1);
	strcpy(round1_msg, id_str);
	strcat(round1_msg, " 1 ");
	strcat(round1_msg, public_key_str);

	// broadcast the round 1 message
	if (sendto(sock, round1_msg, strlen(round1_msg), 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != strlen(round1_msg)){
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("round 1 broadcast: %s\n", round1_msg);
	}

	// open a named pipe and receive the needed message from the "client" running on this node
	// e.g. on node 0, we need to receive a round 1 message from node 2
	if(0 != access(FIFO_NAME, 0)) {
		mkfifo(FIFO_NAME, 0666);
	}
	int fd = open(FIFO_NAME, O_RDONLY);
	char* recv_round1_msg = (char*)calloc(KEY_LEN+1, sizeof(char));
	int num;
	if ((num = read(fd, recv_round1_msg, KEY_LEN+1)) == -1)
            perror("read");
        else {
            printf("read round 1 message- %d bytes: \"%s\"\n", num, recv_round1_msg);
    }
	close(fd);

	// the following will compute g^(priv0)(priv2), if we are at node 0
	BIGNUM *recv_round1_msg_BN = BN_new();
	BN_hex2bn(&recv_round1_msg_BN, recv_round1_msg);
	BN_mod_exp(intermediate_value, recv_round1_msg_BN, private_key, public_mod, ctx);
	printf("intermediate value: %s\n", BN_bn2hex(intermediate_value));

	// construct the round 2 message: <id 2 intermediate_value>
	char* int_value_str = BN_bn2hex(intermediate_value);
	char* round2_msg = (char*)malloc(strlen(int_value_str)+strlen(id_str)+strlen(" 2 ")+1);
	strcpy(round2_msg, id_str);
	strcat(round2_msg, " 2 ");
	strcat(round2_msg, int_value_str);

	// broadcast the round 2 message
	if (sendto(sock, round2_msg, strlen(round2_msg), 0, (struct sockaddr *) 
				&broadcastAddr, sizeof(broadcastAddr)) != strlen(round2_msg)){
		perror("sendto() sent a different number of bytes than expected");
	}
	else {
		printf("round 2 broadcast: %s\n", round2_msg);

	}

	// open a named pipe and receive the needed message from the local client
	// e.g. on node 0, we need to receive a round 2 message from node 1
	fd = open(FIFO_NAME, O_RDONLY);
	char* recv_round2_msg = (char*)calloc(KEY_LEN+1, sizeof(char));
	if ((num = read(fd, recv_round2_msg, KEY_LEN+1)) == -1)
            perror("read");
        else {
            printf("read round 2 message- %d bytes: \"%s\"\n", num, recv_round2_msg);
    }
	close(fd);

	// calculate g^(priv0)(priv1)(priv2), i.e. the shared secret
	BIGNUM *recv_round2_msg_BN = BN_new();
	BN_hex2bn(&recv_round2_msg_BN, recv_round2_msg);
	BN_mod_exp(shared_secret, recv_round2_msg_BN, private_key, public_mod, ctx);
	char* shared_secret_str = BN_bn2hex(shared_secret);
	printf("shared secret: %s\n", shared_secret_str);

	// open the named pipe and send symmetric key to the local client
	fd = open(FIFO_NAME, O_WRONLY);
	if (num = write(fd, shared_secret_str, strlen(shared_secret_str)) == -1)
		perror("write");
	else
		printf("sent the shared secret locally: %s\n", shared_secret_str);
	close(fd);

	BN_clear(public_mod);
	BN_clear(private_key);
	BN_clear(public_key);
	BN_clear(intermediate_value);
	BN_clear(recv_round1_msg_BN);
	BN_clear(recv_round2_msg_BN);
	BN_CTX_free(ctx);
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
	char* id_str = (char*)malloc(16);
	RAND_poll();					  /* seed the RNG */
	BIGNUM *shared_secret = BN_new(); /* the symmetric key used for encryption */

    if (argc < 4)                     /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <ID (0-2)> <IP Address> <Port> \n", argv[0]);
        exit(1);
    }

	id_str = argv[1];
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

	printf("press enter to start key generation\n");
	getchar();

	struct timeval  tv1, tv2;
	gettimeofday(&tv1, NULL);

	generate_keys(id_str, sock, broadcastAddr, shared_secret);

	gettimeofday(&tv2, NULL);
	printf("Time taken to generate keys: %f milliseconds\n", (double) (tv2.tv_sec - tv1.tv_sec) *1000000 + (double) (tv2.tv_usec - tv1.tv_usec));

	unsigned char* shared_secret_str = BN_bn2hex(shared_secret);

    while(1) /* Run forever */
    {
    	/*take input command*/
    	printf("Type in a valid command (add/rm <filename>) \n");
		fgets(sendString, COMMAND_LEN+MAX_FILENAME_LEN, stdin);
		char* command = (char*)calloc(COMMAND_LEN+MAX_FILENAME_LEN+1,sizeof(char));
		strcpy(command, sendString);
		command[strlen(command) - 1] = 0;
		char** cmdArray = checkStr(sendString);
		if((strcmp(toLowerCase(cmdArray[0]), "add") == 0 && cmdArray[1] != NULL && cmdArray[1] != "\n")|| 
			(strcmp(toLowerCase(cmdArray[0]), "rm") == 0 && cmdArray[1] != NULL && cmdArray[1] != "\n")){
         /* Broadcast sendString in datagram to clients every 3 seconds*/
			/*i the command is "add", retrieve the content and write to file*/
			char* msgToSend = (char*)calloc(MAX_MSG_LEN, sizeof(char));
			char* timeStamp = (char*)calloc(TIME_LEN+1, sizeof(char));
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
				char* content = (char*)calloc(MAX_MSG_LEN,sizeof(char));
				fgets(content, MAX_MSG_LEN, stdin);
				content[strlen(content) - 1] = '\0';	//remove the newline character in the content
				strcat(msgToSend, " ");
				strcat(msgToSend, content);
			}

			sendStringLen = strlen(msgToSend);
			msgToSend[sendStringLen] = 0;

			send_encrypted_msg(sock, broadcastAddr, shared_secret_str, msgToSend);

	        sleep(1);   /* Avoids flooding the network */
     	}
     	else{
     		printf("Command not found.\nUsage: add/rm <filename>\n");
     	}
    }
    /* NOT REACHED */
}
