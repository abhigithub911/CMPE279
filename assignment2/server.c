#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#define PORT 8080

int main(int argc, char const *argv[]) {

        // setup a socket connection
   int new_socket = socketSetUp_Privileged();

   int forkedProcess = fork();

   if(forkedProcess==0) {

                char socket_fd[12];
                sprintf(socket_fd,"%d", new_socket);
                char *args[] = {"./EXEC",socket_fd, NULL};

                int error = execvp("./EXEC",args);
                printf("Ending-----: %d",error);
    }

        //Wait for child process to complete
    wait(NULL);

    return 0;

}


int socketSetUp_Privileged() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
    &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address,
    sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
    (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    return new_socket;
}


/*
Steps to run: 
Compile using the following commands: 
gcc child.c -o EXEC
gcc server.c -o server

run as super user
sudo ./server
This will execute the new process called child.c 
same for the client with reduced privileges.
