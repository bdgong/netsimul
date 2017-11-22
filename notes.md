# Records

> Start from Tue 07 Nov 2017 10:48:48 

## Ideas 

Use VirtualBox as simulation tool. 

GUN/Linux as OS, connected by `Internal Network` mode. 

> If change to Cloud environment, only IP addresss be changed?
>> I guess so.

Set guests Ga, Gb, Gr.  Let Gr be the gateway(Rounter), Ga and Gb communicate with each other by Gr.

        ------                          ------
        | Ga |                          | Gb |
        ------                          ------
           |            ------            /|\     
          \|/           | Gr |             |        
           |            ------             |        
           |            /| |               |        
           |             | |               |    
           |             | |/              |    
           --------------- -----------------                                
                                            
> And of course, its bidirectional.                                            
                                            
                                            

## Call For Details 

### Lab1: Connect two VMs

1. Start the dhcpserver.

>       VBoxManage dhcpserver add --netname intnet --ip 192.168.0.1 --netmask 255.255.255.0 --lowerip 192.168.0.3 --upperip
>       192.168.0.253 --enable

2. Create two VMs, set network mode to `Internal Networks`, and name as "intnet".

4G disk space should be enough.

>       root password: moon@ROOT
>       user         : bdg
>       user password: moon@Bdg

>       root password: netsimul!
>       user         : ga
>       user password: ga@Ga

3. Start two VMs.


### Lab2: Sniffe packet 

Define those protocol headers.

1. Fetch packet with `pcap_loop()`.
2. In callback function handle ethernet packet.
3. Handle arp & ip packet.
4. Handle ip datagrams - TCP, UDP, ICMP.

For more see `sniffex.c`.


### Lab3: Inject packet 

1. Let user input some message - `msg`.
2. Manually construct packet `[ether_header + ip_header + udp_header + msg + frame_checksum_sequence]`.

    Notice
    
    - Leave those checksum(just set to 0).
    - The `htons()` method.

3. Inject with `pcap_inject(pcap_t *handler, u_char *buf, size_t buf_size)`.
4. Sniffe packet with `sniffex` and tcpdump.

For more see `injector.c`.


### Lab4: Inject UDP packet as echoclient's message, send to echoserver

1. The tcpdump show bad check sum.

    output with system UDP protocol

        16:22:17.195763 08:00:27:a8:01:cc (oui Unknown) > 08:00:27:05:6e:fb (oui Unknown), ethertype IPv4 (0x0800),
        length 60: (tos 0x0, ttl 64, id 63853, offset 0, flags [DF], proto UDP (17), length 31)
        192.168.0.5.48114 > 192.168.0.3.1314: [udp sum ok] UDP, length 3
        0x0000:  0800 2705 6efb 0800 27a8 01cc 0800 4500
        0x0010:  001f f96d 4000 4011 c007 c0a8 0005 c0a8
        0x0020:  0003 bbf2 0522 000b 6b21 4849 0a00 0000
        0x0030:  0000 0000 0000 0000 0000 0000

    output with injector UDP packet

        16:35:29.387398 08:00:27:a8:01:cc (oui Unknown) > 08:00:27:05:6e:fb (oui Unknown), ethertype IPv4 (0x0800),
        length 60: (tos 0x2,ECT(0), ttl 255, id 4884, offset 0, flags [none], proto UDP (17), length 31, bad cksum 5f27 (->275f)!)
        192.168.0.5.48114 > 192.168.0.3.1314: [bad udp cksum 0x216b -> 0x6b21!] UDP, length 3
        0x0000:  0800 2705 6efb 0800 27a8 01cc 0800 4502
        0x0010:  001f 1314 0000 ff11 5f27 c0a8 0005 c0a8
        0x0020:  0003 bbf2 0522 000b 216b 4849 0a00 0000
        0x0030:  0000 0000 0000 0000 0000 0000

    so, now you see, its just the byte order problem.

    No! the difference at: type of service, ttl, flags, identifier.

    After fix up,

        17:01:00.746197 08:00:27:a8:01:cc (oui Unknown) > 08:00:27:05:6e:fb (oui Unknown), ethertype IPv4 (0x0800),
        length 60: (tos 0x0, ttl 64, id 63853, offset 0, flags [DF], proto UDP (17), length 31, bad cksum 7c0 (->c007)!)
        192.168.0.5.48114 > 192.168.0.3.1314: [bad udp cksum 0x216b -> 0x6b21!] UDP, length 3
        0x0000:  0800 2705 6efb 0800 27a8 01cc 0800 4500
        0x0010:  001f f96d 4000 4011 07c0 c0a8 0005 c0a8
        0x0020:  0003 bbf2 0522 000b 216b 4849 0a00 0000
        0x0030:  0000 0000 0000 0000 0000 0000

    The result shows that the check sum does not need byte order transfer.

For more, see `echoclient.c`, `echoserver.c`.


## References

[协议栈](http://blog.csdn.net/maochengtao/article/details/37729281)

- BSD TCP/IP
- [lwIP](http://savannah.nongnu.org/projects/lwip/)
- uIP
- TinyTCP

[Tcpdump](http://www.tcpdump.org/)

RFCs

- [RFC 791(IP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc791.txt.pdf)
- [RFC 792(ICMP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc792.txt.pdf)
- [RFC 768(UDP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc768.txt.pdf)
- [RFC 793(TCP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc793.txt.pdf)
- [RFC 826(ARP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc826.txt.pdf)

How to close Linux's ARP, ICMP?

- [How to Close ARP?](http://blog.csdn.net/autofei/article/details/5985866)

        $ # close drivers ARP protocol
        $ ifconfig eth0 -arp

        $ # or close kernel's ARP
        $ echo 1 > /proc/sys/net/ipv4/conf/eth0/arp_ignore
        $ echo 2 > /proc/sys/net/ipv4/conf/eth0/arp_announce

        $ # or arptables
        $ arptables A INPUT -j DROP
        $ arptables A OUTPUT -j DROP

- [How to Close ICMP?](http://blog.csdn.net/qq844352155/article/details/49700121)

        $ # to close
        $ echo 1 >/proc/sys/net/ipv4/icmp_echo_ignore_all

        $ # to open
        $ echo 0 >/proc/sys/net/ipv4/icmp_echo_ignore_all

    This setting will be invalid after reboot.


## Extras

Install Debian VM 

* install additions(depends on make,gcc,headers, so need edit sources.list and `aptitude update` first)

        $ su
        $ sh VBoxLinuxAdditions.run 

* edit /etc/apt/sources.list, add 

        deb http://mirrors.ustc.edu.cn/debian/ jessie main contrib non-free

    then install basic development tools

        $ aptitude update
        $ aptitude install -y make cmake gcc g++ linux-headers-`uname -r`

    If the headers install failed, then VBoxLinuxAdditions might not work, the shared folders may not work as well.

* add user to sudo group

        $ su
        $ usermod -aG sudo ga

* set shared folders(depends on additions)

Useful functions

* `int inet_aton(const char * cp, struct in_addr *inp)`

    IP string to bytes.

* `char * inet_ntoa(struct in_addr in)`

    IP bytes to IP string.

Useful headers

* `/usr/include/netinet/in.h`
* `/usr/include/netinet/ether.h`

