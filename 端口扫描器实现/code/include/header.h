#ifndef HEADER_H
#define HEADER_H

#include <iostream>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <semaphore.h>
#include <aio.h>
#include <sys/types.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>

struct TCPConHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
};

struct TCPConThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
};

/**
 * @brief 伪头部结构体，用于TCP和UDP校验和计算
 * 
 * 伪头部用于计算TCP和UDP的校验和，它包含了IP头部中的部分字段。
 */
struct pseudohdr   
{  
	unsigned int saddr;     // 源IP地址
	unsigned int daddr;     // 目的IP地址
	char useless;           // 未使用的字段，填充字节
	unsigned char protocol; // 协议类型（TCP或UDP）
	unsigned short length;  // TCP或UDP数据长度
};  


struct TCPSYNHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct TCPSYNThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};


struct TCPFINThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct UDPThrParam
{
	std::string HostIP;
	unsigned BeginPort;
	unsigned EndPort;
	unsigned LocalHostIP;
};

struct UDPScanHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

struct ipicmphdr 
{ 
	struct iphdr ip; 
	struct icmphdr icmp; 
}; 

struct TCPFINHostThrParam
{
	std::string HostIP;
	unsigned HostPort;
    unsigned LocalPort;
	unsigned LocalHostIP;
};

// IP头部结构体
struct IPHeader {
    unsigned char headerLen : 4;   // 头部长度（单位：32位字节），占4位
    unsigned char version : 4;     // 版本号，IPv4或IPv6，占4位
    unsigned char tos;             // 服务类型，占8位
    unsigned short length;         // 总长度，占16位
    unsigned short ident;          // 标识，占16位
    unsigned short fragFlags;      // 分片偏移和标志位，占16位
    unsigned char ttl;             // 存活时间（TTL），占8位
    unsigned char protocol;        // 协议类型，占8位
    unsigned short checksum;       // 校验和，占16位
    unsigned int srcIP;            // 源IP地址，占32位
    unsigned int dstIP;            // 目的IP地址，占32位

    // 初始化
    IPHeader(unsigned int src, unsigned int dst, int protocol) {
        version = 4;                    // 设置版本号为IPv4
        headerLen = 5;                  // 设置头部长度为5个32位字节（20字节）
        srcIP = src;                    // 设置源IP地址
        dstIP = dst;                    // 设置目的IP地址
        ttl = (char)128;                // 设置存活时间（TTL）为128
        this -> protocol = protocol;    // 设置协议类型
        if (protocol == IPPROTO_TCP) {
            length = htons(20 + 20);    // 如果协议类型为TCP，则设置总长度为20字节（IP头部）+ 20字节（TCP头部）
        } else if (protocol == IPPROTO_UDP) {
            length = htons(20 + 8);     // 如果协议类型为UDP，则设置总长度为20字节（IP头部）+ 8字节（UDP头部）
        }
    }
};


// TCP头部结构体
struct TCPHeader {
    uint16_t srcPort;     // 源端口号，占16位
    uint16_t dstPort;     // 目的端口号，占16位
    uint32_t seq;         // 序列号，占32位
    uint32_t ack;         // 确认号，占32位
    uint8_t null1 : 4;    // 未使用的字段，占4位
    uint8_t length : 4;   // 数据偏移，占4位
    uint8_t FIN : 1;      // FIN标志位
    uint8_t SYN : 1;      // SYN标志位
    uint8_t RST : 1;      // RST标志位
    uint8_t PSH : 1;      // PSH标志位
    uint8_t ACK : 1;      // ACK标志位
    uint8_t URG : 1;      // URG标志位
    uint8_t null2 : 2;    // 未使用的字段
    uint16_t windowSize;  // 窗口大小
    uint16_t checkSum;    // 校验和
    uint16_t ptr;         // 紧急指针
};


/**
 * @brief 计算16位字的校验和
 * 
 * @param ptr 指向数据的指针
 * @param nbytes 数据的字节数
 * @return unsigned short 校验和结果
 */
static inline unsigned short in_cksum(unsigned short *ptr, int nbytes) 
{ 
    register long sum;        // 校验和
    u_short oddbyte;          // 不足16位的字节
    register u_short answer;  // 最终的校验和结果

    sum = 0;                  // 初始化校验和为0
    while(nbytes > 1)         // 遍历数据的每个16位字
    { 
        sum += *ptr++;        // 将每个16位字累加到校验和中
        nbytes -= 2;          // 字节数减去2，因为每次操作都是处理两个字节
    } 

    if(nbytes == 1)           // 如果数据长度为奇数，则处理最后一个不足16位的字节
    { 
        oddbyte = 0;          // 初始化不足16位的字节为0
        *((u_char *) &oddbyte) = *(u_char *)ptr; // 将最后一个字节复制到oddbyte中
        sum += oddbyte;       // 将oddbyte加到校验和中
    } 

    sum = (sum >> 16) + (sum & 0xffff);  // 将校验和的高16位加到低16位上，并清除溢出的高位
    sum += (sum >> 16);                   // 将上一步的溢出值加到低16位上
    answer = ~sum;                        // 取反得到最终的校验和结果

    return(answer);                       // 返回校验和结果
} 


/**
 * @brief 获取本地主机的IP地址
 * 
 * 通过执行系统命令"/sbin/ifconfig"获取本地主机的IP地址。
 * 
 * @return unsigned int 返回本地主机的IP地址（网络字节序）
 */
static inline unsigned int GetLocalHostIP(void) 
{ 
	FILE *fd;                  // 文件指针
	char buf[20] = {0x00};     // 用于存储命令输出结果的缓冲区

	// 执行系统命令并打开文件流，获取本地主机的IP地址信息
	fd = popen("/sbin/ifconfig | grep inet | grep -v 127 | awk '{print $2}' | cut -d \":\" -f 2", "r"); 
	if(fd == NULL)
	{ 
		fprintf(stderr, "cannot get source ip -> use the -f option\n");  // 输出错误信息
		exit(-1);  // 退出程序
	} 
	fscanf(fd, "%20s", buf);  // 从文件流中读取IP地址信息
	return(inet_addr(buf));   // 将字符串形式的IP地址转换为网络字节序的整数形式并返回
} 


bool Ping(std::string HostIP,unsigned LocalHostIP); // ICMP 探测指定主机
void* Thread_TCPconnectHost(void* param); // TCP connect 扫描
void* Thread_TCPconnectScan(void* param);
void* Thread_TCPSYNHost(void* param);
void* Thread_TCPSynScan(void* param);
void* UDPScanHost(void* param);
void* Thread_UDPScan(void* param);
void* Thread_TCPFinScan(void* param);
void* Thread_TCPFINHost(void* param);
#endif
