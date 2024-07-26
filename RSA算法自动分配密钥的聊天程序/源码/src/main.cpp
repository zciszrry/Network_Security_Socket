#include "head.h" 

int main()
{
    std::cout << "Client or Server?" << std::endl;
    char temp;
    std::cin >> temp;
    if(temp == 's') { // 如果选择服务器端
        
        int nListenSocket, nAcceptSocket;
        struct sockaddr_in sLocalAddr, sRemoteAddr;
        bzero(&sLocalAddr, sizeof(sLocalAddr)); // 初始化本地地址
        sLocalAddr.sin_family = PF_INET; // 设置地址族
        sLocalAddr.sin_port = htons(6000); // 设置端口号
        sLocalAddr.sin_addr.s_addr = INADDR_ANY; // 设置IP地址为本地任意IP

        // 创建监听socket
        if ((nListenSocket = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket"); // 输出错误信息
            exit(1); // 退出程序
        }
        // 绑定地址
        if(bind(nListenSocket, (struct sockaddr *) &sLocalAddr, sizeof(struct sockaddr)) == -1) {
            perror("bind");
            exit(1);
        }
        // 监听连接
        if(listen(nListenSocket, 5) == -1) {
            perror("listen");
            exit(1);
        }
        printf("Listening...\n"); //开始监听

        socklen_t nLength = 0;
        // 接受连接
        nAcceptSocket = accept(nListenSocket, (struct sockaddr*)&sRemoteAddr, &nLength);
        close(nListenSocket); // 关闭监听socket
        printf("server: got connection from %s, port %d, socket %d\n",inet_ntoa(sRemoteAddr.sin_addr), ntohs(sRemoteAddr.sin_port), nAcceptSocket);
        
        // 密钥协商
        PublicKey cRsaPublicKey;
        CRsaOperate CRsaOperate;
        cRsaPublicKey = CRsaOperate.GetPublicKey();
        // 发送RSA公钥
        if(send(nAcceptSocket, (char *)(&cRsaPublicKey), sizeof(cRsaPublicKey), 0) != sizeof(cRsaPublicKey)){
            perror("send");
            exit(0);
        }else{
            printf("successful send the RSA public key. \n");
        }
        // 接收DES密钥
        unsigned long long nEncryptDesKey[4];
        char *strDesKey = new char[8];
        if(4*sizeof(unsigned long long) != TotalRecv(nAcceptSocket,(char *)nEncryptDesKey, 4*sizeof(unsigned long long),0)) {
            perror("TotalRecv DES key error");
            exit(0);
        }
        else {
            printf("successful get the DES key\n");
            // 解密DES密钥
            unsigned short * pDesKey = (unsigned short *)strDesKey;
            for(int i = 0;i < 4; i++) {
                pDesKey[i] = CRsaOperate.Decry(nEncryptDesKey[i]);
            }
        }
        
        printf("Begin to chat...\n");
        // 开始加密通信
        SecretChat(nAcceptSocket,inet_ntoa(sRemoteAddr.sin_addr),strDesKey);
        close(nAcceptSocket); // 关闭连接socket
    }
    else { // 如果选择客户端
        std::cout << "Please input the server address:" << std::endl; // 提示输入服务器地址
        char strIPAddr[16];
        std::cin >> strIPAddr; // 输入服务器地址
        int nConnectSocket, nLength;
        struct sockaddr_in sDestAddr;
        if((nConnectSocket = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
            perror("Socket");
            exit(errno);
        }
        int SEVERPORT = 6000;

        sDestAddr.sin_family = AF_INET;
        sDestAddr.sin_port = htons(SEVERPORT);
        sDestAddr.sin_addr.s_addr = inet_addr(strIPAddr);
        // 连接服务器
        if(connect(nConnectSocket, (struct sockaddr *) &sDestAddr, sizeof(sDestAddr)) != 0) {
            perror("Connect");
            exit(errno);
        }
        else {
            printf("Connect Success! \n");
            char *strDesKey = new char [8];
            // 生成DES密钥
            GerenateDesKey(strDesKey);
            printf("Create DES key success\n");
            PublicKey cRsaPublicKey;
            // 接收RSA公钥
            if(sizeof(cRsaPublicKey) == TotalRecv(nConnectSocket,(char *)&cRsaPublicKey, sizeof(cRsaPublicKey),0)) {
                printf("Successful get the RSA public Key\n");
            }
            else {
                perror("Get RSA public key ");
                exit(0);
            }
            // 加密DES密钥并发送给服务器
            unsigned long long nEncryptDesKey[4];
            unsigned short *pDesKey = (unsigned short *)strDesKey;
            for(int i = 0; i < 4; i++) {
                nEncryptDesKey[i] = CRsaOperate::Encry(pDesKey[i],cRsaPublicKey);
            }
            if(sizeof(unsigned long long)*4 != send(nConnectSocket, (char *)nEncryptDesKey,sizeof(unsigned long long)*4, 0)) {
                perror("Send DES key Error");
                exit(0);
            }
            else {
                printf("Successful send the encrypted DES Key\n");
            }
            printf("Begin to chat...\n");
            // 开始加密通信
            SecretChat(nConnectSocket,strIPAddr,strDesKey);
        }
        close(nConnectSocket); // 关闭连接socket
    }
}
