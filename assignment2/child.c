#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char const *argv[]) {

    printf("Privilege of Child Process :: Real user id = %d, Effective User id = %d\n",getuid(),geteuid());
	int setuidToNobody = setuid(65534);
	if(setuidToNobody<0){
        perror("Failed to setuid");
            exit("EXIT_FAILURE");
    }else{
		printf("%d",argc);
        char buffer[1024] = {0};
		int valread;
		char *hello = "Hello from server";
        int new_socket = atoi(argv[1]);

		printf("new_socket : %d \n",new_socket);

		valread = read( new_socket , buffer, 1024);
		printf("%s\n",buffer );
		send(new_socket , hello , strlen(hello) , 0 );
		printf("Hello message sent\n");
        }
    return 0;
}

