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

>       root password: 
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
4. Sniffe packet with `sniffex`.

For more see `injector.c`.

## References

[协议栈](http://blog.csdn.net/maochengtao/article/details/37729281)

- BSD TCP/IP
- uIP
- TinyTCP

[Tcpdump](http://www.tcpdump.org/)

RFCs

- [RFC 791(IP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc791.txt.pdf)
- [RFC 792(ICMP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc792.txt.pdf)
- [RFC 768(UDP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc768.txt.pdf)
- [RFC 793(TCP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc793.txt.pdf)
- [RFC 826(ARP)](https://www.rfc-editor.org/rfc/pdfrfc/rfc826.txt.pdf)


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

