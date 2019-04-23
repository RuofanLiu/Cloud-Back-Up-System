# Cloud-Back-Up-System

A RAID 1 backup system for Raspberry Pi
Each node (Raspberry PI) has a server and a client(receiver). The server broadcasts the data to all the other nodes, and the client receives the data, send ACK to the server. To prevent server from blocking by the fgets() function, another thread is create for receiving ACK from all the other clients.

## Compilation
open two terminals and run the broadcast_server.c and broadcast_receiver.c in these two saperate terminals

```bash
To compile: 
   gcc broadcast_server.c -lssl -lcrypto
   gcc broadcast_receiver.c -o b.out -lssl -lcrypto
To run:
  ./a.out id broadcast_address port
  ./b.out id port
```
When running, id should be an integer from 0-2, where the id of the server and receiver are the same on the same machine
Note: with key generation as is, the program requires 3 machines to be running the code on the same network

## Usage

Follow the interface on the server to play with it.    

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
Please make sure to update tests as appropriate.
