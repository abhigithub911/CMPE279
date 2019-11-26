#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char const *argv[]) {

    int socket_fd,message_fd;
   
   //test seccomp-bpf in child
//   mkdir("test");

    //change the root directory and continue doing unprivileged operations in the new directory path.
    chdir("/tmp");
   // int chroot = chroot("/newMessageInfo");

    if (chroot("/tmp") != 0) {
    //if(chroot != 0) {
        perror("Error while performing chroot");
        return 1;
    } else {
        printf("Privilege of Child Process :: Real user id = %d, Effective User id = %d\n",getuid(),geteuid());
	    int setuidToNobody = setuid(65534);
	    if(setuidToNobody<0){
            perror("Failed to setuid");
            exit("EXIT_FAILURE");
        }else{
		    printf("%d",argc);
            char buffer[1024] = {0};
		    int valread;
		    // char *hello = "Hello from server";
            int new_socket = atoi(argv[1]);

		    printf("new_socket : %d \n",new_socket);

            message_fd=atoi(argv[2]);     
            char readMessage_to_send[1024];
            // @param 1: message_fd - file descriptor
            // @param 2: readMessage_to_send - buffer to read message from
            // @param 3: 1024 - buffer size 
            int a=read(message_fd,readMessage_to_send,1024);
            readMessage_to_send[a]='\0';

            //Message received
            char message_recieved[1024] = {0};
		    valread = read( new_socket , message_recieved, 1024);
		    printf("%s\n",message_recieved );

            // Sending message
		    send(new_socket , readMessage_to_send , strlen(readMessage_to_send) , 0 );
		    printf("Message sent\n", readMessage_to_send);
        }
    }
    
    return 0;
}
