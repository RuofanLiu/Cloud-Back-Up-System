#include <stdio.h>      
#include <sys/socket.h> 
#include <arpa/inet.h>  
#include <stdlib.h>     
#include <string.h>     
#include <unistd.h>     
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define FIFO_NAME "shared_data"
#define MAX_CONTENT_LEN 100000
#define MAX_FILENAME_LEN 64
#define TIME_LEN 25
#define COMMAND_LEN 3
#define MAX_LOG_SIZE 2
#define KEY_LEN 256
#define IV_LEN 128
#define MAX_MSG_LEN MAX_CONTENT_LEN+MAX_FILENAME_LEN+TIME_LEN+COMMAND_LEN  /* Longest string to receive */

int commandSize = 0;    /*records the size of the cmdArray*/
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
    char** rst = (char**)calloc(1024, sizeof(char*));
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
	fclose(file);
    return 0;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
		unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) {
	  perror("could not create ctx");
  }

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
	  perror("decryption init failed");
  }
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
	  perror("decryption update failed");
  }
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
	  perror("decryption final failed");
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

void receive_and_decrypt_msg(int sock, unsigned char* key, char* recv_msg) {
	char* iv_str = calloc(IV_LEN+1, sizeof(char));
	int encrypted_msg_len, num;
	if ((num = recvfrom(sock, iv_str, 129, 0, NULL, 0)) < 0)
		perror("recvfrom() failed");
    printf("Received iv: %s\n", iv_str);    /* Print the received string */

	char* encrypted_msg = calloc(MAX_MSG_LEN+1, sizeof(char));
	if ((encrypted_msg_len = recvfrom(sock, encrypted_msg, MAX_MSG_LEN+1, 0, NULL, 0)) < 0)
		perror("recvfrom() failed");
    printf("Received encrypted msg:\n");
	BIO_dump_fp(stdout, encrypted_msg, encrypted_msg_len);

	unsigned char* decrypted_msg = (unsigned char*)calloc(encrypted_msg_len+1, sizeof(char));

	struct timeval  tv1, tv2;
	gettimeofday(&tv1, NULL);

	int len = decrypt(encrypted_msg, encrypted_msg_len, key, iv_str, recv_msg);
	recv_msg[len] = '\0';

	gettimeofday(&tv2, NULL);
	printf("Time taken to decrypt message: %f microseconds\n", (double) (tv2.tv_sec - tv1.tv_sec) *1000000 + (double) (tv2.tv_usec - tv1.tv_usec));

	printf("decrypted as: %s\n", recv_msg);
}

void generate_keys(int id, int sock, char* shared_secret_str) {
	char* recv_msg = (char*)calloc(KEY_LEN+strlen("1 1 ")+1, sizeof(char));
	char* round2_msg = (char*)calloc(KEY_LEN+1, sizeof(char));
	int fd, num;
	// should receive a total of 6 messages from the servers
	for(int i = 0; i < 6; i++) {
        if ((num = recvfrom(sock, recv_msg, KEY_LEN+strlen("1 1 ")+1, 0, NULL, 0)) < 0)
            perror("recvfrom() failed");

        printf("Received: %s\n", recv_msg);    /* Print the received string */
		char** recv_msg_array = checkStr(recv_msg);
		if(atoi(recv_msg_array[0]) == ((id + 2) % 3) && atoi(recv_msg_array[1]) == 1) {
			fd = open(FIFO_NAME, O_WRONLY);
			if ((num = write(fd, recv_msg_array[2], strlen(recv_msg_array[2]))) == -1)
				perror("write");
			close(fd);
		} else if(atoi(recv_msg_array[0]) == ((id + 2) % 3) && atoi(recv_msg_array[1]) == 2) {
			strcpy(round2_msg, recv_msg_array[2]);
		}
		free(recv_msg_array);
	}
	// once all 6 messages have been received, we know for sure round 1 is over
	fd = open(FIFO_NAME, O_WRONLY);
	if (num = write(fd, round2_msg, strlen(round2_msg)) == -1)
		perror("write");
	close(fd);

	// need to read symmetric key from server
	fd = open(FIFO_NAME, O_RDONLY);
	if ((num = read(fd, shared_secret_str, KEY_LEN+1)) == -1)
            perror("read");
	close(fd);
	unlink(FIFO_NAME);
	free(recv_msg);
	free(round2_msg);
}

int main(int argc, char *argv[])
{
    int sock;                         
    struct sockaddr_in broadcastAddr, Sender_addr; 
    unsigned short broadcastPort;     
    int recvStringLen;                /* Length of received string */
    struct logUnit log[MAX_LOG_SIZE];           /*a log to keep track of the information to stay consistant with other nodes*/
    int logSize = 0;
	int id;
	char* shared_secret_str = (char*)calloc(KEY_LEN+1, sizeof(char));

    if (argc != 3)    /* Test for correct number of arguments */
    {
        fprintf(stderr,"Usage: %s <ID (0-2)> <Broadcast Port>\n", argv[0]);
        exit(1);
    }

    id = atoi(argv[1]);   /* First arg: node id*/
    broadcastPort = atoi(argv[2]);   /* First arg: broadcast port */

    /* Create a best-effort datagram socket using UDP */
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        perror("socket() failed");

    /* Construct bind structure */
    memset(&broadcastAddr, 0, sizeof(broadcastAddr));   
    broadcastAddr.sin_family = AF_INET;                 
    broadcastAddr.sin_addr.s_addr = htonl(INADDR_ANY);  
    broadcastAddr.sin_port = htons(broadcastPort);      

    /* Bind to the broadcast port */
    if (bind(sock, (struct sockaddr *) &broadcastAddr, sizeof(broadcastAddr)) < 0)
        perror("bind() failed");

	char* gen = calloc(COMMAND_LEN+1, sizeof(char));
	int num;
	if ((num = recvfrom(sock, gen, COMMAND_LEN+1, 0, NULL, 0)) < 0)
		perror("recvfrom() failed");
    printf("Received generation command\n");
	free(gen);

	// open named pipe to share generation command
	if(0 != access(FIFO_NAME, 0)) {
		mkfifo(FIFO_NAME, 0666);
	}
	int fd = open(FIFO_NAME, O_WRONLY);
	if (num = write(fd, "gen", strlen("gen")) == -1)
		perror("write");
	close(fd);

	struct timeval  tv1, tv2;
	gettimeofday(&tv1, NULL);

	generate_keys(id, sock, shared_secret_str);

	gettimeofday(&tv2, NULL);
	printf("Time taken to generate keys: %f microseconds\n", (double) (tv2.tv_sec - tv1.tv_sec) *1000000 + (double) (tv2.tv_usec - tv1.tv_usec));

    while(1) {
        /* Receive a single datagram from the server */
		char* recvString = (char*)calloc(MAX_MSG_LEN+1, sizeof(char)); /* Buffer for received string */
		receive_and_decrypt_msg(sock, shared_secret_str, recvString);

		recvStringLen = strlen(recvString);
        recvString[recvStringLen] = '\0';

        /*Create a local log for the server to read*/
        FILE* fp;
        fp = fopen("log.txt", "a+");
        fputs(recvString, fp);
        fputs("\n", fp);
        fclose(fp);

        /*Create user log to guarantee data consistency*/
        struct logUnit lu;
		// add test.txt Tue Apr 23 00:01:52 2019 asdf
        char** cmdArray = checkStr(recvString);
        lu.command = (char*)calloc(COMMAND_LEN+1, sizeof(char));
        lu.filename = (char*)calloc(MAX_FILENAME_LEN+1, sizeof(char));
        lu.time = (char*)calloc(TIME_LEN+1, sizeof(char));
        strcpy((lu.command), cmdArray[0]);
        strcpy((lu.filename), cmdArray[1]);
        strcpy((lu.time), cmdArray[2]);
        for(int i = 3; i < 7; ++i){
            strcat((lu.time), " ");
            strcat((lu.time), cmdArray[i]);
        }
        /* if the command is add, add the content to the log as well*/
        lu.content = (char*)calloc(MAX_CONTENT_LEN+1, sizeof(char));
        if(strcmp(lu.command, "add") == 0){
            strcpy((lu.content), cmdArray[7]);
            for(int i = 8; i < commandSize; ++i){
                strcat(lu.content, " ");
                strcat(lu.content, cmdArray[i]);
            }
        }
		lu.content[strlen(lu.content)] = '\0';

        /*The log only keeps track of MAX_LOG_SIZE most recent logs*/
        if(logSize == MAX_LOG_SIZE){
            for(int i = 0; i < MAX_LOG_SIZE - 1; ++i){
                log[i] = log[i + 1];
            }
            log[MAX_LOG_SIZE - 1] = lu;
        }
        else{
            log[logSize] = lu;
            logSize++;
        }

        /*create or remove file baed on the command received from server*/
        if(strcmp(lu.command, "add") == 0){
            FILE* file;
            file = fopen(lu.filename, "w+");
            fputs(lu.content, file);   //write content to file
            printf("%s added\n", lu.filename);
            fclose(file);
        }
        else if(strcmp(lu.command, "rm") == 0){
            if(checkExistence(lu.filename) == 0){
                int status = remove(lu.filename);
                if(status == 0){
                    printf("%s deleted\n", lu.filename);
                }
            }
            else{
                printf("Target file does not exist\n");
            }
        }
		free(lu.command);
		free(lu.filename);
		free(lu.time);
		free(lu.content);
		free(recvString);
		free(cmdArray);
    }
    close(sock);
    exit(0);
}
