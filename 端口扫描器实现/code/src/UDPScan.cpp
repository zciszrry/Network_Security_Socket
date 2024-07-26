#include "header.h"

// 互斥锁，用于控制 UDP 扫描线程的打印操作
pthread_mutex_t UDPPrintlocker = PTHREAD_MUTEX_INITIALIZER;

// UDP 扫描主机函数
void* UDPScanHost(void* param) {
    // 获取参数结构体
    struct UDPScanHostThrParam *p = (struct UDPScanHostThrParam*)param;
    // 提取参数信息
    std::string HostIP = p->HostIP;
    unsigned HostPort = p->HostPort;
    unsigned LocalPort = p->LocalPort;
    unsigned LocalHostIP = p->LocalHostIP;

    // 创建 UDP 原始套接字
    int UDPSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (UDPSock < 0) {
        pthread_mutex_lock(&UDPPrintlocker);
        std::cout << "Can't create raw ICMP socket !" << std::endl;
        pthread_mutex_unlock(&UDPPrintlocker);
    }

    // 设置套接字选项
    int on = 1;
    int ret = setsockopt(UDPSock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (ret < 0) {
        pthread_mutex_lock(&UDPPrintlocker);
        std::cout << "Can't set raw socket !" << std::endl;
        pthread_mutex_unlock(&UDPPrintlocker);
    }

    // 设置 UDP 扫描主机地址结构体
    struct sockaddr_in UDPScanHostAddr;
    memset(&UDPScanHostAddr, 0, sizeof(UDPScanHostAddr));
    UDPScanHostAddr.sin_family = AF_INET;
    UDPScanHostAddr.sin_addr.s_addr = inet_addr(&HostIP[0]);
    UDPScanHostAddr.sin_port = htons(HostPort);

    // 构造 UDP 数据包
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr)];
    memset(packet, 0x00, sizeof(packet));
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct pseudohdr *pseudo = (struct pseudohdr *)(packet + sizeof(struct iphdr) - sizeof(struct pseudohdr));

    // 设置 UDP 头部字段
    udp->source = htons(LocalPort);
    udp->dest = htons(HostPort);
    udp->len = htons(sizeof(struct udphdr));
    udp->check = 0;

    // 设置伪首部
    pseudo->saddr = LocalHostIP;
    pseudo->daddr = inet_addr(&HostIP[0]);
    pseudo->useless = 0;
    pseudo->protocol = IPPROTO_UDP;
    pseudo->length = udp->len;

    // 计算校验和
    udp->check = in_cksum((u_short *)pseudo, sizeof(struct udphdr) + sizeof(struct pseudohdr));

    // 设置 IP 头部字段
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0x10;
    ip->tot_len = sizeof(packet);
    ip->frag_off = 0;
    ip->ttl = 69;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr("192.168.1.168");
    ip->daddr = inet_addr(&HostIP[0]);

    // 发送 UDP 数据包
    int n = sendto(UDPSock, packet, ip->tot_len, 0, (struct sockaddr *)&UDPScanHostAddr, sizeof(UDPScanHostAddr));
    if (n < 0) {
        pthread_mutex_lock(&UDPPrintlocker);
        std::cout << "Send message to Host Failed !" << std::endl;
        pthread_mutex_unlock(&UDPPrintlocker);
    }

    // 将套接字设置为非阻塞模式
    if (fcntl(UDPSock, F_SETFL, O_NONBLOCK) == -1) {
        pthread_mutex_lock(&UDPPrintlocker);
        std::cout << "Set socket in non-blocked model fail !" << std::endl;
        pthread_mutex_unlock(&UDPPrintlocker);
    }

    // 接收 ICMP 响应数据包
    struct timeval TpStart, TpEnd;
    struct ipicmphdr hdr;
    gettimeofday(&TpStart, NULL); // 获取开始时间
    do {
        // 接收响应消息
        n = read(UDPSock, (struct ipicmphdr *)&hdr, sizeof(hdr));

        if (n > 0) {
            // 判断是否为 ICMP 目的不可达消息
            if ((hdr.ip.saddr == inet_addr(&HostIP[0])) && (hdr.icmp.code == 3) && (hdr.icmp.type == 3)) {
                pthread_mutex_lock(&UDPPrintlocker);
                std::cout << "Host: " << HostIP << " Port: " << HostPort << " closed !" << std::endl;
                pthread_mutex_unlock(&UDPPrintlocker);
                break;
            }
        }
        // 判断是否超时
        gettimeofday(&TpEnd, NULL);
        float TimeUse = (1000000 * (TpEnd.tv_sec - TpStart.tv_sec) + (TpEnd.tv_usec - TpStart.tv_usec)) / 1000000.0;
        if (TimeUse < 3) {
            continue;
        } else {
            pthread_mutex_lock(&UDPPrintlocker);
            std::cout << "Host: " << HostIP << " Port: " << HostPort << " closed !" << std::endl;
            pthread_mutex_unlock(&UDPPrintlocker);
            break;
        }
    } while (true);

    // 关闭套接字
    close(UDPSock);
    // 释放参数结构体内存
    delete p;
}


void* Thread_UDPScan(void* param) {
    // 获取参数结构体
    struct UDPThrParam *p = (struct UDPThrParam*)param;
    std::string HostIP = p->HostIP;
    unsigned BeginPort = p->BeginPort;
    unsigned EndPort = p->EndPort;
    unsigned LocalHostIP = p->LocalHostIP;

    // 设置本地端口起始值
    unsigned LocalPort = 1024;

    // 遍历需要扫描的端口范围
    for (unsigned TempPort = BeginPort; TempPort <= EndPort; TempPort++) {
        // 创建 UDP 扫描主机参数结构体
        UDPScanHostThrParam *pUDPScanHostParam = new UDPScanHostThrParam;
        pUDPScanHostParam->HostIP = HostIP;
        pUDPScanHostParam->HostPort = TempPort;
        pUDPScanHostParam->LocalPort = TempPort + LocalPort;
        pUDPScanHostParam->LocalHostIP = LocalHostIP;
        UDPScanHost(pUDPScanHostParam);
    }

    // 扫描线程退出消息
    std::cout << "UDP Scan thread exit !" << std::endl;
    pthread_exit(NULL);
}
