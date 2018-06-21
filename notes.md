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

>       root password: netsimul!
>       user         : gr2
>       user password: gr2@Gr2

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


## Implementations

Network protocols run as a process (M), each Socket application run as another process, communication with shared memory, synchronize by signal.

### Socket

对于UDP:
应用程序Socket端，创建，关闭socket，能够发送和接收数据
协议层Socket端，接受创建，关闭请求，处理发送和接收数据

对于协议层Socket的接收，需要确定应用程序端口号向应用程序Socket进行分发（可以将应用进程ID和端口号绑定，指定进程ID发送信号，数据里也放一个进程ID，进程取数据时再次检查该ID是否和本进程ID一致）
对于协议层Socket的发送，也许需要向应用程序Socket反馈发送状态

CProtoSocket

- `_pendingAccept`

    Recording accept requests by their port number, after handle such a request, remove corresponding port number. 

--------------------


对于TCP:
应用程序Socket端，创建，监听，接收连接，发起连接，关闭，发送数据，接收数据
协议层Socket端，接受创建，监听，接收连接，发起连接，关闭请求，处理发送和接收数据

在协议层完成三次握手四次挥手，完成后通知应用程序Socket


### Transport: TCP

#### Send

> Check those theories from 'Computer Networking A Top-Down Approach 6th'.

暂时只实现异步发送

- 将应用程序数据放入发送缓冲区之后就返回，启动发送
- 每发送一段报文都对该报文启用一个重传定时器，若定时器超时则进行重传
- 当接收到ACK之后，从发送缓冲区删除该报文并取消重传定时器，若发送缓冲区不为空，继续发送下一段报文
- 当接收到ACK但检测到窗口为零时，启动零窗口探测定时器

发送的三种方式

- Stop-and-Wait protocol (very low efficiency)
- piplining protocol, Go-Back-N
- piplining protocol, Selective Repeat (most efficient)

Piplining protocol as a sliding-window protocol, the window size used to flow control and congestion control. 

可靠传输的手段

- Check sum
- Timer
- Sequence
- Acknowledgment
- Negative acknowledgment
- Window, pipelining

Problems: 

1. 缓冲区队列如何设计？

    暂定为结构`list<shared_ptr<packet_t>>`, 通过`packet_t`的control buffer标志每个段的起始和结束sequence等信息

2. 关于ACK的值的具体含义？

    猜想a. 表示该数值之前的数据都收到了。按照这个理解的话，譬如收到一个ACK=3000，这个ACK表示3000以前的数据都收到了，
    可以发送后续数据，但是，万一这个ACK本该是后于ACK=2100达到呢，也就是说，2100之前的数据还未被确认，是收到了乱序
    的数据，矛盾，因此这个猜想不完全正确；
    猜想b. 表示该数值之前的一定长度数据都收到了。同样以上面的例子，ACK=3000，收到了数值为3000的确认，但只能表示2100
    到3000之间的数据都收到了，当ACK=2100超时，再次发送对应的该段数据，当收到ACK=2100后，填充了缺失数据，这个猜想
    理论上似乎是正确的。再举例，client以{seq=5,ack=0}向server发起连接请求，server以{seq=1,ack=6}回复，client以
    {seq=6,ack=2}回复连接成功，此时client{seq=7,ack=2}, server{seq=2,ack=7}.  client先后发送1000{seq=7,ack=2},
    1000{seq=1007,ack=2},200{seq=2007,ack=2}个字节给server，因为server没有回复数据，所以client的ack一直是2，client
    的seq根据数据大小递增，而server回复依次回复{seq=1,ack=1007},{seq=1,ack=2007},{seq=1,ack=2207}，总共传输了2200
    个字节。按照猜想b，sender至少应该保存起始seq，结束seq（应该收到的ack）才能知道成功接收了多少字节。receiver可以用链表
    保存收到的数据包，按照seq递增排序。但是如果是这样，合并ACK又是什么意思呢？



#### Receive

### Transport: UDP

### IP

Only implement slow fragment(there is no fragment queue).

Avoid noise by add option value 0xFF020000. According to RFC 791(IP) options rule, use case 2, format as {option-type,
option-length, and the actual option-data}. The first 16 bits is what we use, followed by 16 bits padding zeros. And, for
option-type(0xFF), we set copied flag to 1, which means copy option to all fragments on fragmentation, set option class
to 3, which is reserved before, set option number to 31(or another between 0~31 since we get 5 bits). For option-length,
we do not have extra option data, so just option-type and option-length count to 2 bytes. That's why we get 0xFF020000.


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

After all those steps, reboot is needed

Useful functions

* `int inet_aton(const char * cp, struct in_addr *inp)`

    IP string to bytes.

* `char * inet_ntoa(struct in_addr in)`

    IP bytes to IP string.

Useful headers

* `/usr/include/netinet/in.h`
* `/usr/include/netinet/ether.h`

Capture with `tcpdump`

* Capture UDP packet and save to capture.log file

        sudo tcpdump -vvv -xx udp | tee capture.log

* Capture host 211.67.27.254 packets and print while capture

        sudo tcpdump -nl -vvv -xx host 211.67.27.254 | tee capture.log

* About TCP

    When a SYN segment send to an unknown host, reply is SYN | RST. 

Debug by GDB

* Signal handle

        handle SIGUSR1 nostop pass print
        handle SIGUSR2 nostop pass print

