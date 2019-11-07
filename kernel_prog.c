#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/delay.h>


#include <linux/init.h>
#include <linux/skbuff.h>
#include "linux/fs.h"
#include <linux/proc_fs.h>
#include "linux/errno.h"
#include "linux/uaccess.h"

#include <linux/timer.h> //也供计时器使用
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/socket.h>


#define STATUS_MAXNUM 1000
#define NETLINK_PRTCLNO 17
#define MAX_LIFE 5

#define TCP_PRTCL 6
#define UDP_PRTCL 17
#define ICMP_PRTCL 1

#define RULE_AMOUNT 32

#define LINK_AMOUNT 2048
#define LINKALIVE 32

// Save the PID
int uspid;
// Current defalut mode
int def_mode=1; // 1=permit, 0=reject, init w/ 0
// Hook Options structures
static struct nf_hook_ops in_filter;		// NF_INET_PRE_ROUTING - for incoming packets
static struct nf_hook_ops out_filter;	// NF_INET_POST_ROUTING - for outgoing packets
// Declare Netlink Socket
static struct sock *netlinkfd = NULL;
//timer
struct timer_list linkstate_timer;
void refresh_alivetime(unsigned long d);

// Msg handling function
void msgReceive(struct sk_buff *__skb);
void msgSend(char *info);
//Execution function
int filterFunction(struct sk_buff *skb); //packet in, ACPT/DCLE out
int convertString(char *command);

//Rule management
int addrule(char *srcaddr,int srcport,char *dstaddr,int dstport,int ptlno,int log,int action);
int delrule(int rlno);
void listrule();
void saverule();
void setpolicy(int pno);
// Link management
int find_linkstate(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol);
int hash_function(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol);
int insert_linkstate(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol,int p_log);
void delete_linkstate(int num);
//
int rule_check(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol,int *p_log);
void log_packet(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol, int permit);



//Support
 char* strtok(char* string_org,const char* demial);
 int atoi(const char *nptr);
 char *strcpy(char *dst, const char *src);
 void ip2str(unsigned long int ip, unsigned char * str);
 unsigned long int str2ip(char * str);
int translateipmask(char * addrstr, unsigned long int * ip, unsigned long int * mask);
 
 //
 void debuginfo();
 
 //////////////////////////////////////////
 //structures for linktable and ruletable//
 //////////////////////////////////////////
 struct linkstate
 {
	int valid;
	unsigned long int srcip; 
	int srcport;
	unsigned long int dstip;
	int dstport;
	char protocol;
	int alivetime;
	int log;
 };
 
 struct rule
 {
	int valid;
	unsigned long int srcip;
	unsigned long int srcmask;
	int srcport;
	unsigned long int dstip;
	unsigned long int dstmask;
	int dstport;
	char protocol;
	int log;
	int permit;
 };
 
 struct linkstate lshm[LINK_AMOUNT];
 struct rule rltbl[RULE_AMOUNT];
 int rulecount=0;
 /////////////////////
 //hook function /////
 /////////////////////
unsigned int inhookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
			
	int retval;
	retval = filterFunction(skb);
	if(retval==1) 
	{
		//printk("Accepted--\n");
		return NF_ACCEPT;
	}
	else 
	{
		//printk("Dropped--\n");
		return NF_DROP;
	}
}

unsigned int outhookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		)
{
	int retval;
	retval = filterFunction(skb);
	if(retval==1) 
	{
		//printk("Accepted--\n");
		return NF_ACCEPT;
	}
	else 
	{
		//printk("Dropped--\n");
		return NF_DROP;
	}
}

int filterFunction(struct sk_buff *skb)
{   //retval : 1=accept, 0=drop
	char common_addr_buf1[25];
	char common_addr_buf2[25];
	// The Network Layer Header
	struct iphdr *ip_header;
	
	//I2P3
	unsigned long int p_srcip, p_dstip; // _be32
	int p_srcport, p_dstport;
	char p_protocol; // _u8
	
	//pre check
	if(!skb) return 0;//packet is null
	ip_header = (struct iphdr *)skb_network_header(skb);//gain ip header
	if ( !ip_header ) return 0; // ip header is null
	
	//Gain IP address and protocol from ip header
	p_srcip = (unsigned long int) (ntohl(ip_header->saddr));
	p_dstip = (unsigned long int) (ntohl(ip_header->daddr));
	p_protocol = ip_header->protocol;
	
	//main logic
	if(p_protocol == TCP_PRTCL)
	{
		//complete five elements
		struct tcphdr *tcp_header;
		tcp_header = tcp_hdr(skb);
		p_srcport = ntohs(tcp_header->source);
		p_dstport = ntohs(tcp_header->dest);
		
		//print pkt info
		//ip2str(p_srcip,common_addr_buf1);
		//ip2str(p_dstip,common_addr_buf2),
		//printk("PKT[from %s:%d to %s:%d prtcl=%d syn=%d]--",common_addr_buf1,p_srcport,common_addr_buf2,p_dstport,p_protocol,tcp_header->syn);
		
		
		//find the link 
		if(find_linkstate(p_srcip, p_srcport, p_dstip, p_dstport, p_protocol)==1) return 1;
		else
		{//if not found
#ifdef DEBUG
			//(struct tcphdr *)((u8 *)ip_header+(ip_header->ihl<<2));
			printk("[TCP:seq=%d,ackseq=%d,fin=%d,syn=%x,rst=%x,psh=%d,ack=%d,urg=%d,sport=%ld]",tcp_header->seq,tcp_header->ack_seq,
			tcp_header->fin,((struct tcphdr *)((u8 *)ip_header+(ip_header->ihl<<2)))->syn,tcp_header->rst,tcp_header->psh,tcp_header->ack,tcp_header->urg,((struct tcphdr *)((u8 *)ip_header+(ip_header->ihl<<2)))->source);
			
#endif
			if(((struct tcphdr *)((u8 *)ip_header+(ip_header->ihl<<2)))->syn)//if it is a tcp SYN
			{
				int tlog=0;
				if(rule_check(p_srcip, p_srcport, p_dstip ,p_dstport, p_protocol, &tlog)==1)
				{// check rules before adding rule
					if(insert_linkstate(p_srcip, p_srcport, p_dstip, p_dstport, p_protocol,tlog)==0)
					return 1;
				else 
					{//if link table is full
						printk("!!!Link Table Max Loaded!!!\n");
						return 0;
					}
				}
			}
			else return 0;	
		}
		
		
	}
	else if(p_protocol == UDP_PRTCL)
	{
		//complete five elements
		struct udphdr *udp_header;
		udp_header = udp_hdr(skb);
        p_srcport = ntohs(udp_header->source);
		p_dstport = ntohs(udp_header->dest);
		
		//print pkt info
		//ip2str(p_srcip,common_addr_buf1);
		//ip2str(p_dstip,common_addr_buf2);
		//printk("PKT[from %s:%d to %s:%d prtcl=%d]--",common_addr_buf1,p_srcport,common_addr_buf2,p_dstport,p_protocol);
		
		//
		if(find_linkstate(p_srcip, p_srcport, p_dstip, p_dstport, p_protocol)==1) return 1;
		else
		{
			int tlog=0;
			if(rule_check(p_srcip, p_srcport, p_dstip ,p_dstport, p_protocol, &tlog)==1)
			{
				if(insert_linkstate(p_srcip, p_srcport, p_dstip, p_dstport, p_protocol,tlog)==0)
					return 1;
				else 
					{
						printk("!!!Link Table Max Loaded!!!\n");
						return 0;
					}
			}
			else return 0;
		}
		 
	}
	else if(p_protocol == ICMP_PRTCL)
	{
		//print pkt info
		//ip2str(p_srcip,common_addr_buf1);
		//ip2str(p_dstip,common_addr_buf2);
		//printk("PKT[from %s to %s prtcl=%d]--",common_addr_buf1,common_addr_buf2,p_protocol);
		
		
		// ICMP has no port, set the port as 0
		if(find_linkstate(p_srcip, 0, p_dstip, 0, p_protocol)==1) return 1;
		else
		{
			int tlog=0;
			if(rule_check(p_srcip, 0, p_dstip ,0, p_protocol,&tlog)==1)
			{
				if(insert_linkstate(p_srcip, 0, p_dstip, 0, p_protocol,tlog)==0)
					return 1;
				else 
					{
						printk("!!!Link Table Max Loaded!!!\n");
						return 0;
					}
			}
			else return 0;
		}
		
		
	}
	// No match
	else
	{	
		//print pkt info
		//ip2str(p_srcip,common_addr_buf1);
		//ip2str(p_dstip,common_addr_buf2);	
		//printk("PKT[from %s to %s prtcl=%d]--",common_addr_buf1,common_addr_buf2,p_protocol);
		return def_mode;
	}
}

/////////////////////////////////
//Init/Close module         /////
//Netfilter and Netlink     /////
/////////////////////////////////

int init_module()
{	

	// Initialize Pre-Routing Filter
	printk("\nFirewall Started\n");
	in_filter.hook	= (nf_hookfn *)&inhookfn;// 钩子调用的函数
	in_filter.pf		= PF_INET;	// 协议族 IPv4要使用PF_INET
	in_filter.hooknum	= NF_INET_PRE_ROUTING;		// 五种钩子中选一
	in_filter.priority	= NF_IP_PRI_FIRST;		// 优先级

	// Initialize Post-Routing Filter
	out_filter.hook	= (nf_hookfn *)&outhookfn;// 钩子调用的函数
	out_filter.pf	= PF_INET;	// 协议族 IPv4要使用PF_INET
	out_filter.hooknum	= NF_INET_POST_ROUTING;		// 五种钩子中选一
	out_filter.priority	= NF_IP_PRI_FIRST;		// 优先级
	
	// Register hooks
	// 注册钩子
	nf_register_hook(&in_filter);
	nf_register_hook(&out_filter);
	printk("Hooks Registered\n");
	
	// init hash table
	memset(lshm,0,LINK_AMOUNT*sizeof(struct linkstate));
	
	// init rule tbl
	memset(rltbl,0,RULE_AMOUNT*sizeof(struct rule));
	

	init_timer(&linkstate_timer);//初始化定时器
	linkstate_timer.expires = jiffies + HZ;   //设置触发时间为1s
	linkstate_timer.function = refresh_alivetime;    //触发时执行函数refresh_alivetime
	linkstate_timer.data = 0; //触发执行函数的长整形参数
	add_timer(&linkstate_timer);    //向内核注册定时器


    // Create netlink socket
	netlinkfd = netlink_kernel_create(&init_net, NETLINK_PRTCLNO, 0, msgReceive, NULL, THIS_MODULE);
	//该创建指定msgReceive作为消息处理函数
	if(!netlinkfd)
	{
		printk(KERN_ERR "Cannot Create Netlink Socket. Exit\n");
		return -1;
	}
	else
	{
		printk("Netlink on Socket Established\n");
		return 0;
	}
	

}

void cleanup_module()
{
	// Unregister hooks
	nf_unregister_hook(&in_filter);
	nf_unregister_hook(&out_filter);

	del_timer(&linkstate_timer);//删除定时器
	
	if(netlinkfd)
	sock_release(netlinkfd->sk_socket);
	printk("Netlink Socket Released\n");
	
	printk("\nFirewall Stopped\n");
}

///////////////////////////////
//Netlink message handling   //
///////////////////////////////

void msgReceive(struct sk_buff *__skb)
{
	int retval;
	
	//Declare Structures
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;

	char *confirmation = "Comfirmed by Kernel";
	char *errormsg1 = "Invalid Argument";
	char *errormsg2 = "Logical Error";
	char *errormsg3 = "Out of Allocated Space";
    printk("Kernel Received a Message");
	
	//获取Socket Buffer中的内容
    skb = skb_get(__skb);
	
	if(skb->len >= sizeof(struct nlmsghdr)){
		nlh = (struct nlmsghdr *)skb->data;
		if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
		&& (__skb->len >= nlh->nlmsg_len)){
			uspid = nlh->nlmsg_pid; //Get the PID of Userspace for Sending Confirmation
			printk(", Content=[%s]",(char *)NLMSG_DATA(nlh));
#ifdef DEBUG	
			printk(", state=A");
#endif
			printk("\n");
			retval=convertString((char *)NLMSG_DATA(nlh));
			if(retval==0)
			{
			msgSend(confirmation);// Send back a confirmation
			}
			else if(retval==-1)
			{
				msgSend(errormsg1);
			}
			else if(retval==-2)
			{
				msgSend(errormsg2);
			}		
			else if(retval==-3)
			{
				msgSend(errormsg3);
			}
				
		}
	}else{
		printk(", Content=[%s]",(char *)NLMSG_DATA(nlmsg_hdr(__skb)));
#ifdef DEBUG
		printk(", state=B");
#endif		
		printk("\n");
		retval=convertString((char *)NLMSG_DATA(nlmsg_hdr(__skb)));
			if(retval==0) msgSend(confirmation);// Send back a confirmation
			else if(retval==-1)
				msgSend(errormsg1);
			else if(retval==-2)
				msgSend(errormsg2);		
			else if(retval==-3)
				msgSend(errormsg3);				
	
	}
	kfree_skb(skb);//释放Socket缓冲区
}

void msgSend(char *text)
{
	int size;
	struct sk_buff *skb;
	unsigned char *old_tail;
	struct nlmsghdr *nlh;
	int retval;
	//Get the len of text
	size = NLMSG_SPACE(strlen(text));
	skb = alloc_skb(size, GFP_ATOMIC);
	//Fill the buffer
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(text))-sizeof(struct nlmsghdr), 0); 
	old_tail = skb->tail;
	memcpy(NLMSG_DATA(nlh), text, strlen(text));
	nlh->nlmsg_len = skb->tail - old_tail;
	// Prepare to send
	NETLINK_CB(skb).pid = 0;
	NETLINK_CB(skb).dst_group = 0;
    retval = netlink_unicast(netlinkfd, skb, uspid, MSG_DONTWAIT);
	printk(KERN_DEBUG "Kernel Sent a Message (Unicast Retval=%d)\n",retval);
}

///////////////////////////////
//Convert and Execute (Rule) //
///////////////////////////////

int convertString(char *command)
{
//retval:
// 0 normal, -1 argument error, -2 logical error -3 space full
	char	*token;
	
	token = strtok(command, " ");
	//以空格分割输入 按照第一个单词判断功能
	
	if(!strcmp(token,"add"))//add a rule
	{
		char srcaddr[21];
		int srcport;
		char dstaddr[21];
		int dstport;
		char prtcl[5];
		int ptlno;
		int log; // 1 yes 0 no
		int action; // 1 permit 0 reject
		

		//src address		
		token = strtok(NULL, " "); if(!token) return -1;
		strcpy(srcaddr,token);
		//src port 
		token = strtok(NULL, " "); if(!token) return -1;
		sscanf(token,"%d",&srcport);
		if(srcport<0||srcport>65535) return -2;
		//set address
		token = strtok(NULL, " "); if(!token) return -1;
		strcpy(dstaddr,token);
		//dst port 
		token = strtok(NULL, " "); if(!token) return -1;
		sscanf(token,"%d",&dstport);
		if(dstport<0||dstport>65535) return -2;
	    //protocol
		token = strtok(NULL, " "); if(!token) return -1;
		strcpy(prtcl,token);
		if(!strcmp(prtcl,"tcp")) ptlno=TCP_PRTCL;
		else if (!strcmp(prtcl,"udp")) ptlno=UDP_PRTCL;
		else if (!strcmp(prtcl,"icmp")) ptlno=ICMP_PRTCL;
		else return -2;
		//log or not
		token = strtok(NULL, " "); if(!token) return -1;
		if(!strcmp(token,"y")) log=1;
		else if(!strcmp(token,"n")) log=0;
		else return -1;
		//permit or reject
		token = strtok(NULL, " "); if(!token) return -1;
		if(!strcmp(token,"permit")) action=1;
		else if(!strcmp(token,"reject")) action=0;
		else return -1;
		
		return addrule(srcaddr,srcport,dstaddr,dstport,ptlno,log,action);
	}
	else if(!strcmp(token,"del"))//delete a rule
	{
		int rlno;

		//continue to read one parameter
		token = strtok(NULL, " "); if(!token) return -1;
		rlno=atoi(token); if(rlno<0) return -2;
		return delrule(rlno);
		
	}
	else if(!strcmp(token,"list"))//list all rules
	{
		
		printk("Start to list rules\n");
		listrule();
		return 0;
	}
	else if(!strcmp(token,"save"))//save rules
	{
		
		printk("Start to save rules\n");
		saverule();
		return 0;
	}
	else if(!strcmp(token,"set"))//set default policy
	{
		int policy;//0=default reject, 1=default permit
		//continue to read one parameter
		token = strtok(NULL, " "); if(!token) return -1;
		policy = atoi(token); if(policy!=0&&policy!=1) return -2;
		printk("Start to set default policy:\ndefault permit=%d\n",policy);
		setpolicy(policy);
		return 0;
	}
	else if(!strcmp(token,"debug"))//display all info
	{
		printk("Calling debuginfo()\n");
		debuginfo();
		return 0;
	}
	else return -1;
	
}

int translateipmask(char * addrstr, unsigned long int * ip, unsigned long int * mask)
{
	
	int tmp; int tmpcnt;
	char ipaddrbuf[20]; 
    char maskbuf[10]; //A small buffer causes overflow!!!!!

	//Do consider mask and non-mask situation!!
	memset(ipaddrbuf,0,20);
	memset(maskbuf,0,10);
	tmp=-1;
	for(tmpcnt=0;addrstr[tmpcnt]!=0;tmpcnt++)
	{
		if(addrstr[tmpcnt]=='/')
			tmp = tmpcnt;
	}
	if(tmp!=-1)
	{
		memcpy(ipaddrbuf,addrstr,tmp);
		memcpy(maskbuf,addrstr+tmp+1,tmpcnt-(tmp));
	}
	else
	{
		memcpy(ipaddrbuf,addrstr,tmpcnt);
		maskbuf[0]='0';
	}
	
	*ip = (unsigned long int)ntohl(str2ip(ipaddrbuf)); //important to add NTOHL
#ifdef DEBUG
	printk("[DEBUG[%x]]",*ip);
#endif
	sscanf(maskbuf,"%d",&tmp);
	if(tmp>=32||tmp<0) return -2;
	*mask = (~0)<<(32-tmp);
	
	return 0;
}



int addrule(char *srcaddr,int srcport,char *dstaddr,int dstport,int ptlno,int log,int action)
{ // retval -3=space full, 0=okay, -2=argument error
	if(rulecount>=RULE_AMOUNT) //check space in rule table
	{
		printk("!!!Rule table max load!!!\n");
		return -3;
	}
	
	
	unsigned long int srcip, dstip;
	unsigned long int srcmask, dstmask;
	//convert string to number
	if(translateipmask(srcaddr, &srcip, &srcmask)==-2) 
	{
		printk("Invalid argument\n");
		return -2;
	}
	if(translateipmask(dstaddr, &dstip, &dstmask)==-2)
	{
		printk("Invalid argument\n");
		return -2;
	}
	
	//add a rule in the rule table
	rltbl[rulecount].valid = 1;
	rltbl[rulecount].srcip = srcip;
	rltbl[rulecount].srcmask = srcmask;
	rltbl[rulecount].dstip = dstip;
	rltbl[rulecount].dstmask = dstmask;
	rltbl[rulecount].srcport = srcport;
	rltbl[rulecount].dstport = dstport;
	rltbl[rulecount].protocol = ptlno;
	rltbl[rulecount].log = log;
	rltbl[rulecount].permit = action;
	
	
	//debug
	char common_addr_buf1[25];
	char common_addr_buf2[25];
	ip2str(rltbl[rulecount].srcip,common_addr_buf1);
	ip2str(rltbl[rulecount].dstip,common_addr_buf2),
	printk(KERN_DEBUG"Rule %d Added [from %15s/%x:%-5d to %15s/%x:%-5d prtcl=%-2d log=%1d permit=%1d]\n",rulecount,
						common_addr_buf1,rltbl[rulecount].srcmask,rltbl[rulecount].srcport,
						common_addr_buf2,rltbl[rulecount].dstmask,rltbl[rulecount].dstport,
						rltbl[rulecount].protocol,rltbl[rulecount].log,rltbl[rulecount].permit);
	
	//manage number
	rulecount++;
	
	
	return 0;
	
}

int delrule(int rlno)
{
	//retval -1=invalid number 0=normal
	if(rlno>=rulecount||rlno<0)
	{
		return -1;
	}
	int sttmp;
	for(sttmp=rlno;sttmp<rulecount-1;sttmp++)
	{
		rltbl[sttmp]=rltbl[sttmp+1];
	}
	rltbl[sttmp].valid=0;
	
	
	printk("Rule %d Deleted\n",rlno);
	rulecount--;
	
	return 0;
	
	
	
}

void listrule()
{
	
	char common_addr_buf1[25];
	char common_addr_buf2[25];
	int cnt;
	printk(KERN_DEBUG"--------------------------\n");
	printk(KERN_DEBUG"|RULE TABLE\n---------------");
	for(cnt=0;cnt<rulecount;cnt++)
	{
		if(rltbl[cnt].valid==0) continue;
	ip2str(rltbl[cnt].srcip,common_addr_buf1);
	ip2str(rltbl[cnt].dstip,common_addr_buf2),
	printk(KERN_DEBUG"|[%d][from %15s/%x:%-5d to %15s/%x:%-5d prtcl=%-2d log=%1d permit=%1d]\n",cnt,
						common_addr_buf1,rltbl[cnt].srcmask,rltbl[cnt].srcport,
						common_addr_buf2,rltbl[cnt].dstmask,rltbl[cnt].dstport,
						rltbl[cnt].protocol,rltbl[cnt].log,rltbl[cnt].permit);
	
	}
	printk(KERN_DEBUG"--------------------------\n");
	
}

void saverule()
{
	struct file * fd = NULL;
	mm_segment_t fs;
	loff_t pos;
	char common_addr_buf1[25];
	char common_addr_buf2[25];
	char logbuf[2048];
	char rulebuf[128];
	
	fd = filp_open("rule.log",O_RDWR|O_CREAT,0640);
	
	fs = get_fs();
	set_fs(KERNEL_DS);
	pos=0;
	int tmprcnt = 0;
	for(tmprcnt=0;tmprcnt<rulecount;tmprcnt++)
	{
		if(rltbl[tmprcnt].valid==0) continue;
		ip2str(rltbl[tmprcnt].srcip,common_addr_buf1);
		ip2str(rltbl[tmprcnt].dstip,common_addr_buf2);
		sprintf(rulebuf,"[Rule %d] [from %15s/%x:%-5d to %15s/%x:%-5d prtcl=%-2d log=%1d permit=%1d]\n",tmprcnt,
						common_addr_buf1,rltbl[tmprcnt].srcmask,rltbl[tmprcnt].srcport,
						common_addr_buf2,rltbl[tmprcnt].dstmask,rltbl[tmprcnt].dstport,
						rltbl[tmprcnt].protocol,rltbl[tmprcnt].log,rltbl[tmprcnt].permit);
		strcat(logbuf,rulebuf);
	}
	
	vfs_write(fd,logbuf,strlen(logbuf),&pos);
	filp_close(fd,NULL);
	
}

void setpolicy(int pno)
{
	def_mode = pno;
}

void log_packet(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol, int permit)
{
	char common_addr_buf1[25];
	char common_addr_buf2[25];
	printk("[LOG]");
	ip2str(p_srcip,common_addr_buf1);
	ip2str(p_dstip,common_addr_buf2),
	printk("[pkt from %s:%d to %s:%d prtcl=%d]",common_addr_buf1,p_srcport,
	common_addr_buf2,p_dstport,p_protocol);
	if(permit==1) printk("[ACCEPTED]\n");
	else printk("[REJECTED]\n");
}

int rule_check(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol,int *p_log)
{ // retval 1=accept, 0=reject 
 // default mode is taken into consideration in this function 
	int cnt;

#ifdef DEBUG	
	printk("[Start to Check Rules]");
#endif
	for(cnt=0;cnt<rulecount;cnt++)
	{
#ifdef DEBUG
		printk("[v=%d (%d),sport=%d and %d (%d), dport=%d and %d (%d),prtl=%d and %d (%d),sip=%ld and %ld(diff=%d,test=%d),dip=%ld and %ld(diff=%d,test=%d), Result=(%d)]",	
		rltbl[cnt].valid,rltbl[cnt].valid==1,
		rltbl[cnt].srcport,p_srcport,rltbl[cnt].srcport==p_srcport,
		rltbl[cnt].dstport,p_dstport,rltbl[cnt].dstport==p_dstport,
		rltbl[cnt].protocol,p_protocol,rltbl[cnt].protocol==p_protocol,
		p_srcip&rltbl[cnt].srcmask,
		rltbl[cnt].srcip&rltbl[cnt].srcmask,(p_srcip&rltbl[cnt].srcmask-rltbl[cnt].srcip&rltbl[cnt].srcmask),
		(((p_srcip&rltbl[cnt].srcmask)^(rltbl[cnt].srcip&rltbl[cnt].srcmask))==0), //////Still do not know why???? Difference is 0, but not equal??????
		p_dstip&rltbl[cnt].dstmask,
		rltbl[cnt].dstip&rltbl[cnt].dstmask,(p_dstip&rltbl[cnt].dstmask-rltbl[cnt].dstip&rltbl[cnt].dstmask),
		(((p_dstip&rltbl[cnt].dstmask)^(rltbl[cnt].dstip&rltbl[cnt].dstmask))==0), /////Today's biggest bug

		rltbl[cnt].valid==1&&rltbl[cnt].srcport==p_srcport&&rltbl[cnt].dstport==p_dstport&&
		rltbl[cnt].protocol==p_protocol&&((((p_srcip&rltbl[cnt].srcmask)^(rltbl[cnt].srcip&rltbl[cnt].srcmask))==0))&&
		((((p_srcip&rltbl[cnt].srcmask)^(rltbl[cnt].srcip&rltbl[cnt].srcmask))==0)));
#endif	
		if(rltbl[cnt].valid==1&&rltbl[cnt].srcport==p_srcport&&rltbl[cnt].dstport==p_dstport&&
		rltbl[cnt].protocol==p_protocol&&((((p_srcip&rltbl[cnt].srcmask)^(rltbl[cnt].srcip&rltbl[cnt].srcmask))==0))&&
		((((p_srcip&rltbl[cnt].srcmask)^(rltbl[cnt].srcip&rltbl[cnt].srcmask))==0)))
		{
			#ifdef DEBUG
			printk("[RULE FOUND]");
			#endif
			*p_log = rltbl[cnt].log;
			if(rltbl[cnt].log==1)
			{
				log_packet(p_srcip, p_srcport, p_dstip ,p_dstport, p_protocol, rltbl[cnt].permit);
			}
			
			return rltbl[cnt].permit;
		}
	}
	#ifdef DEBUG
	printk("[RULE NOT FOUND, Use Default Mode]");
	#endif
	return def_mode;
}

void debuginfo()
{
	int cnt=0;
	//print pkt info
	
		
	char common_addr_buf1[25];
	char common_addr_buf2[25];

	
	printk(KERN_DEBUG"LINK TABLE\n---------------");
	for(;cnt<LINK_AMOUNT;cnt++)
	{
		if(lshm[(cnt)%LINK_AMOUNT].valid==0) continue;
		ip2str(lshm[(cnt)%LINK_AMOUNT].srcip,common_addr_buf1);
		ip2str(lshm[(cnt)%LINK_AMOUNT].dstip,common_addr_buf2),
		printk(KERN_DEBUG"[%-5d][from %15s:%-5d to %15s:%-5d prtcl=%-3d ttl=%2d]\n",cnt,
						common_addr_buf1,lshm[(cnt)%LINK_AMOUNT].srcport,
						common_addr_buf2,lshm[(cnt)%LINK_AMOUNT].dstport,
						lshm[(cnt)%LINK_AMOUNT].protocol,lshm[(cnt)%LINK_AMOUNT].alivetime);
	}
	printk(KERN_DEBUG"--------------------------\n");
	
}

/////////////////
//linktable /////
/////////////////



int find_linkstate(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol)
{
	
#ifdef DEBUG
	printk("[DEBUG LOG]");
	log_packet(p_srcip, p_srcport, p_dstip ,p_dstport, p_protocol, def_mode);
#endif
	//retval 1=found, 0=not found
	int startpoint;
	int cnt=0;
	startpoint = hash_function(p_srcip, p_srcport, p_dstip,p_dstport, p_protocol);
#ifdef DEBUG
	printk("START TO LOOK FOR LINK");
#endif
	for(;cnt<LINK_AMOUNT;cnt++)
	{
		if(lshm[(startpoint+cnt)%LINK_AMOUNT].valid==0) continue; //If not valid, continue
		else
		{ 
			if((lshm[(startpoint+cnt)%LINK_AMOUNT].srcip==p_srcip && 
			   lshm[(startpoint+cnt)%LINK_AMOUNT].dstip==p_dstip &&
			   lshm[(startpoint+cnt)%LINK_AMOUNT].srcport==p_srcport &&
			   lshm[(startpoint+cnt)%LINK_AMOUNT].dstport==p_dstport &&
			   lshm[(startpoint+cnt)%LINK_AMOUNT].protocol==p_protocol) ||
			   (lshm[(startpoint+cnt)%LINK_AMOUNT].srcip==p_dstip && 
			   lshm[(startpoint+cnt)%LINK_AMOUNT].dstip==p_srcip &&
			   lshm[(startpoint+cnt)%LINK_AMOUNT].srcport==p_dstport &&
			   lshm[(startpoint+cnt)%LINK_AMOUNT].dstport==p_srcport &&
			   lshm[(startpoint+cnt)%LINK_AMOUNT].protocol==p_protocol)
			   )
			   {
				   #ifdef DEBUG
				   printk("[LINK FOUND]");
				   #endif
				   if(lshm[(startpoint+cnt)%LINK_AMOUNT].log==1) 
					   log_packet(p_srcip, p_srcport, p_dstip ,p_dstport, p_protocol, 1);
				   return 1;//return only when all match
			   }	
		}
		//else go to next round
	}
	#ifdef DEBUG
	printk("[LINK NOT FOUND]");
	#endif
	return 0;
}

int hash_function(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol)
{
	return (((p_srcip-p_dstip)+(p_srcport-p_dstport))*p_protocol)%LINK_AMOUNT;
}


int insert_linkstate(unsigned long int p_srcip,int p_srcport,unsigned long int p_dstip,int p_dstport,char p_protocol, int p_log)
{//retval -1=No more space, 0=OK

	int startpoint;
	int cnt=0;
	startpoint = hash_function(p_srcip, p_srcport, p_dstip,p_dstport, p_protocol);
	for(;cnt<LINK_AMOUNT;cnt++)
	{
		if(lshm[(startpoint+cnt)%LINK_AMOUNT].valid==0)
		{
			lshm[(startpoint+cnt)%LINK_AMOUNT].srcip = p_srcip;
			lshm[(startpoint+cnt)%LINK_AMOUNT].dstip = p_dstip;
			lshm[(startpoint+cnt)%LINK_AMOUNT].srcport = p_srcport;
			lshm[(startpoint+cnt)%LINK_AMOUNT].dstport = p_dstport;
			lshm[(startpoint+cnt)%LINK_AMOUNT].protocol = p_protocol;
			lshm[(startpoint+cnt)%LINK_AMOUNT].log = p_log;
			
			lshm[(startpoint+cnt)%LINK_AMOUNT].alivetime = LINKALIVE;
			
			lshm[(startpoint+cnt)%LINK_AMOUNT].valid = 1;
			return 0;
		}
		else continue;
	}
	return -1; //after the loop and no space found
}

void delete_linkstate(int num)
{
	lshm[num].valid=0;
}


void refresh_alivetime(unsigned long d)
{
	mod_timer(&linkstate_timer, jiffies + HZ); //modify the timer to current + 1s
	int cnt = 0;
	for(;cnt<LINK_AMOUNT;cnt++)
	{
		if(lshm[cnt].valid==1) // only change the time of valid items
		{
			lshm[cnt].alivetime--;
			if(lshm[cnt].alivetime == 0) //delete expired linkstates
			{
				delete_linkstate(cnt);
			}
		}
		
	}
}

//////////////////////////////////
//Supportive Functions       /////
////////////////////////////////// 

char*  strtok(char* string_org,const char* demial) {

	static unsigned char* last; 
	unsigned char* str;         
	const unsigned char* ctrl = (const unsigned char*)demial;
	unsigned char map[32]; 
	int count;

	for (count =0; count <32; count++){
		map[count] = 0;
	}   
	do {
		map[*ctrl >> 3] |= (1 << (*ctrl & 7));
	} while (*ctrl++);     
	if (string_org){
		str = (unsigned char*)string_org;
	} else{
		str = last;
	}
	while ((map[*str >> 3] & (1 << (*str & 7)))  && *str){
		str++;
	} 
	string_org = (char*)str; 
	for (;*str; str++){
		if ( map[*str >> 3] & (1 << (*str & 7))){
			*str++ = '\0';
			break;         
		}         
	}    
	last =str;    
	if (string_org == (char*)str){
		return NULL; 
	}else{
		return string_org;
	}
}



int isspace(int x)
{
 if(x==' '||x=='\t'||x=='\n'||x=='\f'||x=='\b'||x=='\r') return 1;
 else    return 0;
}

int isdigit(int x)
{
 if(x<='9'&&x>='0')         
  return 1; 
 else 
  return 0;
}

int atoi(const char *nptr)
{
        int c;              /* current char */
        int total;         /* current total */
        int sign;           /* if '-', then negative, otherwise positive */
       /* skip whitespace */
        while ( isspace((int)(unsigned char)*nptr) )
            ++nptr;
        c = (int)(unsigned char)*nptr++;
        sign = c;           /* save sign indication */
        if (c == '-' || c == '+')
            c = (int)(unsigned char)*nptr++;    /* skip sign */
      total = 0;
        while (isdigit(c)) {
            total = 10 * total + (c - '0');     /* accumulate digit */
            c = (int)(unsigned char)*nptr++;    /* get next char */
        }
     if (sign == '-')
            return -total;
     else   return total;   /* return result, negated if necessary */
}

 void ip2str(unsigned long int ip, unsigned char * str)
 {
	 unsigned char ipchar[4];
	 ipchar[3] = ip%256; ip /= 256;
	 ipchar[2] = ip%256; ip /= 256;
	 ipchar[1] = ip%256; ip /= 256;
	 ipchar[0] = ip%256; ip /= 256;
	 sprintf(str, "%d.%d.%d.%d", ipchar[0],ipchar[1],ipchar[2],ipchar[3]);
 }
 
  unsigned long int str2ip(char * str)
  {
	  int a,b,c,d;
	  char arr[4];
	  sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
	  arr[0]=a; arr[1]=b; arr[2]=c; arr[3]=d;
	  return *(unsigned int *)arr;
  }
 