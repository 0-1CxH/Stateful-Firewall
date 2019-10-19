# Stateful Firewall

## Introduction

This project is a stateful firewall based on Linux Netfilter. It contains two parts of code: Internal firewall and external connector.
The internal firewall, running as kernel module, handles with Netfilter hooks, interprocess communication, firewall logic control and etc. 
The external connector is the remote for transmitting user's commands to the inside, like adjusting the filter rules, checking status and etc.

## Usage

The internal kernel module starts with insmod \*.ko and stops with rmmod \*.ko. Commands used by external connector are listed below.
### Rule 

#### Add
\> userspace\_prog add *source\_ip/mask src\_port dest\_ip/mask dest\_port protocol\_name log\_or\_not permit\_or\_reject* 

e.g.: [run add 123.123.123.1/24 12345 111.112.113.1/24 10000 tcp y permit] 
is going to accept any tcp packet from 123.123.123.1/24:12345 towards 111.112.113.1/24:10000 and all packets will be logged.

e.g.: [run add 123.123.123.123 9876 111.112.113.114 5000 udp n reject] 
is going to drop all udp packet from 123.123.123.123:9876 towards 111.112.113.114:5000 and no packets will be logged.

e.g.: [run add 123.123.123.123 0 111.112.113.114 0 icmp y reject] 
is going to drop all icmp packet from 123.123.123.123 towards 111.112.113.114 and all packets will be logged. Since icmp has no port, the ports are set to 0.


#### Delete

\> userspace\_prog del *rule\_number*

e.g.: [run del 0]
is going to delete rule 0.

#### List/Save

\> userspace\_prog list

This command takes no argument and prints rule table in dmesg.

\> userspace\_prog save

This command takes no argument and prints rule table in log file (default: rule.log).

### Set

#### Default Policy

\> userspace\_prog set *defult_mode*

e.g.: [run set 0]
changes the default policy to reject, which means all packets are dropped if no rule can be matched.

e.g.: [run set 1]
changes the default policy to permit, which means all packets are accepted if no rule can be matched.

Usually, setting to 0 is more secure.

## Internal Firewall

Internal firewall has several important components. 

### Filter

Netfilter is a framework provided by Linux kernel 2.4. The Netfilter hook system is the core of how packets are controlled.
There are five hooks in ip network, they are NF\_INET_PRE_ROUTING, NF\_INET\_LOCAL\_IN, NF\_INET\_FORWARD, NF\_INET\_POST\_ROUTING and NF\_INET\_LOCAL\_OUT, checking at different location of packet flow.
Hooks are registered and started in init_module process, and unregistered in cleanup_module.
Filter functions are attached to hook. The main logic is in the hook function.

Include: linux/netfilter_ipv4.h

APIs Used: nf\_register\_hook, nf\_register\_hook

Documentation: https://netfilter.org/documentation/


### Communication

Internal firewall needs to communicate with external connector (running in userspace). The frequently used methods of interprocess communication between kernel and userspace are: syscall, device(ioctl), /proc, Netlink...
In this project, Netlink is deployed to complete the mission. Netlink socket is interface provided by Linux kernel for IPC, unlike other sockets, this only travels through ports in one single host.
There are data structures related to Netlink, like msghdr and nlmsghdr, are intended to be used with its APIs. 

Include: linux/netlink.h

APIs Used (For kernel part): netlink\_kernel\_create, netlink\_unicast, sock\_release

Documentation: http://man7.org/linux/man-pages/man7/netlink.7.html

### Link Management

Link state is the main idea of a stateful firewall. If a link (like established TCP link) or a virtual link (like ICMP echo or DNS query) exists in the link table of firewall,
the subsequent packets of the link will be accepted without further checking. The link management part of the program examines, looks up for and delete links. When a packet comes,
link manager tells whether it belongs to an existing link, if not, then send it to rule manager. Hash table is used to build link table for efficiency. 

Include: linux/timer.h (Timer is needed for removing expired links)

APIs Used: init\_timer, add\_timer, mod\_timer, del\_timer

Did not use kernel hash library. Built a simple one instead.

### Rule Management

Rule is user-defined filter logic. The rule manager handles modifying rule table, setting default policy and checking link establish request (sent from link manager) per defined rules.
If commands from external connector are got, rule manager adjusts rule table by adding, deleting, displaying or saving; If new request from link manager is obtained, it tracerses rule table for matching a response.
Linear table is used for efficiency and convenience. 


## External Connector

### Communication

### Command Conversion

