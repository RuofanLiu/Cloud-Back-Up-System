# Cloud-Back-Up-System

A RAID 1 backup system for Raspberry Pi
Each node (Raspberry PI) has a server and a client(receiver). The server broadcasts the data to all the other nodes, and the client receives the data, send ACK to the server. To prevent server from blocking by the fgets() function, another thread is create for receiving ACK from all the other clients.

## Compilation
open two terminal and run the broadcast_server.c and broadcast_server.c in these two saperate terminals


```bash
To compile: 
   gcc broadcast_server.c -pthread
   gcc broadcast_receiver.c -o b.out
To run:
  ./a.out broadcast_address port
  ./b.out port
```

## Usage

Follow the interface on the server to play with it.    

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
Please make sure to update tests as appropriate.

