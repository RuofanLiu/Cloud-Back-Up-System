# Cloud-Back-uP-System
A RAID 1 backup system for Raspberry Pi
Each node (Raspberry PI) has a server and a client(receiver). The server broadcasts the data to all the other nodes, and the client receives the data, send ACK to the server. To prevent server from blocking by the fgets() function, another thread is create for receiving ACK from all the other clients.
Usage:
To upload the code to the Raspberry Pi:
    scp path_to_file pi@<ip_address_of_pi>:~/path_of_pi
To run the code:
    open two terminal and run the broadcast_server.c and broadcast_server.c in these two saperate terminals
    To compile: 
      gcc broadcast_server.c -pthread
      gcc broadcast_receiver.c -o b.out
    To run:
      ./a.out broadcast_address port
      ./b.out port
Follow the interface on the server to play with it.    
