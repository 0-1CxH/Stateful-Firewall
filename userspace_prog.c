#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>
#define MAX_PAYLOAD 1024 // maximum payload size
#define NETLINK_PRTCLNO 17


int main(int argc, char* argv[])
{
    int state;
    struct sockaddr_nl src_addr, dest_addr; //Declare Netlink Addresses
    struct nlmsghdr *nlh = NULL; //Netlink Message Header
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;//Declare socket file descriptor
    int state_smg = 0;
	
    // Create a socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_PRTCLNO);
    if(sock_fd == -1){
        printf("error getting socket: %s", strerror(errno));
        return -1;
    }
	
    // Fill the info about src
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); //Set current PID as src port
    src_addr.nl_groups = 0;
	
    //Bind the socket to NL address
    retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0){
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }
	
    // Malloc space for NL msg header
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return -1;
}

	//Fill the info about dst
    memset(&dest_addr,0,sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; //Set kernel's pid(0) as dst port
    dest_addr.nl_groups = 0;
	
	//Fill NL msg Header and Payload
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = src_addr.nl_pid;
    nlh->nlmsg_flags = 0;
	
	int cnt_argv=1;
	char payload_buffer[MAX_PAYLOAD];
	memset(payload_buffer,0,MAX_PAYLOAD);
	for(;cnt_argv<argc;cnt_argv++)
	{
		strcat(payload_buffer,argv[cnt_argv]);
		strcat(payload_buffer," ");
	}
if(payload_buffer[strlen(payload_buffer)-1]==' ')
		payload_buffer[strlen(payload_buffer)-1]=0;
    strcpy(NLMSG_DATA(nlh),payload_buffer); //Set message body
   
   //Link iovec and NL msg header
	iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
   
   //Fill msg header and link iovec,sockaddr
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
	
    //send message
    printf("Sending Message [%s] To %d\n",(char *) NLMSG_DATA(nlh),dest_addr.nl_pid);
    state_smg = sendmsg(sock_fd,&msg,0);
    if(state_smg == -1)
    {
        printf("get error sendmsg = %s\n",strerror(errno));
    }
    memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
	
    //receive message
    
   // while(1){
        printf("Waiting For Confirmation\n");
        state = recvmsg(sock_fd, &msg, 0);
        if(state<0)
        {
            printf("state error\n");
        }
        printf("Received Message: [%s]\n",(char *) NLMSG_DATA(nlh));
   // }
    close(sock_fd);
    return 0;
}
