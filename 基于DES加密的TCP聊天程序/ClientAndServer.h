#include"DES_EncryAndDecry.h"

int a=1;

/**
 * 从套接字接收数据，直到接收到指定长度的数据或发生错误。
 * 
 * @param s 套接字描述符
 * @param buf 接收数据的缓冲区
 * @param len 要接收的数据的长度
 * @param flags 接收操作的标志，通常为 0
 * @return 返回接收到的数据的总字节数，或者在发生错误时返回 -1
 */

ssize_t TotalRecv(int s, void *buf, size_t len, int flags)
{
    size_t nCurSize = 0; // 已经接收的数据字节数
    while (nCurSize < len)
    {
        // 从套接字接收数据，存储到缓冲区中
        ssize_t nRes = recv(s, ((char *)buf) + nCurSize, len - nCurSize, flags);
        if (nRes < 0 || nRes + nCurSize > len) // 如果接收错误或接收到的数据超出了缓冲区的大小，则返回错误
        {
            return -1;
        }
        nCurSize += nRes; // 更新已接收的数据字节数
    }
    return nCurSize; // 返回接收到的数据的总字节数
}

void SecretChat(int nSock, char *pRemoteName, const char *pKey)
{
    CDesOperate cDes; // 创建 DES 操作对象

    // 检查密钥长度是否为8
    if (strlen(pKey) != 8)
    {
        printf("key length must be 8\n");
        return;
    }

    pid_t nPid;
    nPid = fork(); // 创建子进程
    if (nPid != 0) // 父进程
    {
        while (1)
        {
            char strSocketBuffer[max_msg_len]; // 套接字数据缓冲区
            bzero(&strSocketBuffer, max_msg_len); // 清空缓冲区

            int nLength = 0; // 接收数据长度
            nLength = TotalRecv(nSock, strSocketBuffer, max_msg_len, 0); // 接收数据
            if (nLength != max_msg_len) // 接收到数据长度不等于缓冲区大小时，跳出循环
            {
                break;
            }
            else
            {
                string strDecryBuffer; // 解密后的数据字符串
                // 解密接收到的数据
                cDes.decry_operation(string(strSocketBuffer), string(pKey), strDecryBuffer);

                // 打印接收到的消息
                printf("receive message from <%s>: %s\n", pRemoteName, strDecryBuffer.c_str());
                
                // 检查是否收到退出命令
                if (strncmp("quit", strDecryBuffer.c_str(), 4) == 0)
                {
                    printf("Quit！\n");
                    break;
                }
            }
        }
    }
    else // 子进程
    {
        while (1)
        {
            char strStdinBuffer[max_msg_len]; // 标准输入缓冲区
            bzero(&strStdinBuffer, max_msg_len); // 清空缓冲区

            while(strStdinBuffer[0]==0)
            {
                // 从标准输入读取数据
                if (fgets(strStdinBuffer, max_msg_len, stdin) == NULL)
                {
                    continue;
                }
            }
            
            char strEncryBuffer[max_msg_len]; // 加密后的数据缓冲区
            int nLen = max_msg_len; // 加密后数据的长度

            // 将 char 数组转换为 string
            string strStdin(strStdinBuffer);
            string key(pKey);

            // 加密数据
            string encryptedData;
            cDes.encry_operation(strStdinBuffer, string(pKey), encryptedData);
            
            // 将 string 转换为 char* 数组
            strncpy(strEncryBuffer, encryptedData.c_str(), max_msg_len);
            //printf("after DES: %s\n",strEncryBuffer);


            // 发送加密后的数据到套接字
            if (send(nSock, strEncryBuffer, nLen, 0) != nLen)
            {
                perror("send");
            }
            else
            {
                // 检查是否发送退出命令
                if (strncmp("quit", strStdinBuffer, 4) == 0)
                {
                    printf("Quit！\n");
                    break;
                }
            }
        }
    }
}



int client()
{
    printf("Please enter the server address:  ");
    char strIpAddr[16]; 
    cin >> strIpAddr; // 输入 IP 地址

    int nConnectSocket, nLength; //套接字描述符和长度
    struct sockaddr_in sDestAddr; // 目标地址

    // 创建套接字
    if ((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Socket"); // 如果套接字创建失败，则打印错误消息
        exit(errno); 
    }

    // 初始化目标地址结构
    sDestAddr.sin_family = AF_INET; // 设置地址族为 IPv4
    sDestAddr.sin_port = htons(tcp_port); // 设置端口号
    sDestAddr.sin_addr.s_addr = inet_addr(strIpAddr); // 设置 IP 地址

    // 连接到服务器
    if (connect(nConnectSocket, (struct sockaddr *) &sDestAddr, sizeof(sDestAddr)) != 0) 
    {
        perror("Connect "); // 如果连接失败，则打印错误消息
        exit(errno); // 退出程序并返回错误代码
    }
    else
    {
        printf("Connect Success! \nBegin to chat...\n"); // 打印连接成功的消息
        SecretChat(nConnectSocket,strIpAddr,"benbenmi"); // 开始密聊
    }

    close(nConnectSocket); // 关闭套接字
    return 0;
}

int server()
{

    int nListenSocket, nAcceptSocket;
    struct sockaddr_in sLocalAddr, sRemoteAddr;
    socklen_t nLength = sizeof(sRemoteAddr); // 声明一个变量用于存储远程地址结构体的长度

    // 创建监听套接字
    if ((nListenSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        perror("socket"); // 如果创建套接字失败，则打印错误消息
        exit(1);
    }

    // 初始化本地地址结构
    memset(&sLocalAddr, 0, sizeof(sLocalAddr)); // 清空结构体
    sLocalAddr.sin_family = AF_INET; // 设置地址族为 IPv4
    sLocalAddr.sin_port = htons(tcp_port); // 设置端口号
    //sLocalAddr.sin_addr.s_addr = htonl(INADDR_ANY); // 设置 IP 地址为本地任意可用地址

    char server_ip[INET_ADDRSTRLEN];

    printf("Enter IP address: ");
    scanf("%s", server_ip);

    if(inet_pton(AF_INET, server_ip, &sLocalAddr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    // 将套接字与本地地址绑定
    if (bind(nListenSocket, (struct sockaddr *) &sLocalAddr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind"); // 如果绑定失败，则打印错误消息
        exit(1); // 退出程序并返回错误代码
    }

    // 开始监听套接字
    if (listen(nListenSocket, 5) == -1) 
    {
        perror("listen"); // 如果监听失败，则打印错误消息
        exit(1); // 退出程序并返回错误代码
    }
    printf("Listening……");

    // 接受连接请求，并返回新的套接字用于通信
    nAcceptSocket = accept(nListenSocket, (struct sockaddr *) &sRemoteAddr, &nLength);
    close(nListenSocket); // 关闭监听套接字

    // 打印连接信息
    printf("server: got connection from %s, port %d, socket %d\n",
           inet_ntoa(sRemoteAddr.sin_addr), ntohs(sRemoteAddr.sin_port), nAcceptSocket);

    // 开始密聊
    SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), "benbenmi");

    close(nAcceptSocket); // 关闭通信套接字
    return 0;
}



