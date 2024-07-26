#include"DES_EncryAndDecry.h"

int a=1;

/**
 * ���׽��ֽ������ݣ�ֱ�����յ�ָ�����ȵ����ݻ�������
 * 
 * @param s �׽���������
 * @param buf �������ݵĻ�����
 * @param len Ҫ���յ����ݵĳ���
 * @param flags ���ղ����ı�־��ͨ��Ϊ 0
 * @return ���ؽ��յ������ݵ����ֽ����������ڷ�������ʱ���� -1
 */

ssize_t TotalRecv(int s, void *buf, size_t len, int flags)
{
    size_t nCurSize = 0; // �Ѿ����յ������ֽ���
    while (nCurSize < len)
    {
        // ���׽��ֽ������ݣ��洢����������
        ssize_t nRes = recv(s, ((char *)buf) + nCurSize, len - nCurSize, flags);
        if (nRes < 0 || nRes + nCurSize > len) // ������մ������յ������ݳ����˻������Ĵ�С���򷵻ش���
        {
            return -1;
        }
        nCurSize += nRes; // �����ѽ��յ������ֽ���
    }
    return nCurSize; // ���ؽ��յ������ݵ����ֽ���
}

void SecretChat(int nSock, char *pRemoteName, const char *pKey)
{
    CDesOperate cDes; // ���� DES ��������

    // �����Կ�����Ƿ�Ϊ8
    if (strlen(pKey) != 8)
    {
        printf("key length must be 8\n");
        return;
    }

    pid_t nPid;
    nPid = fork(); // �����ӽ���
    if (nPid != 0) // ������
    {
        while (1)
        {
            char strSocketBuffer[max_msg_len]; // �׽������ݻ�����
            bzero(&strSocketBuffer, max_msg_len); // ��ջ�����

            int nLength = 0; // �������ݳ���
            nLength = TotalRecv(nSock, strSocketBuffer, max_msg_len, 0); // ��������
            if (nLength != max_msg_len) // ���յ����ݳ��Ȳ����ڻ�������Сʱ������ѭ��
            {
                break;
            }
            else
            {
                string strDecryBuffer; // ���ܺ�������ַ���
                // ���ܽ��յ�������
                cDes.decry_operation(string(strSocketBuffer), string(pKey), strDecryBuffer);

                // ��ӡ���յ�����Ϣ
                printf("receive message from <%s>: %s\n", pRemoteName, strDecryBuffer.c_str());
                
                // ����Ƿ��յ��˳�����
                if (strncmp("quit", strDecryBuffer.c_str(), 4) == 0)
                {
                    printf("Quit��\n");
                    break;
                }
            }
        }
    }
    else // �ӽ���
    {
        while (1)
        {
            char strStdinBuffer[max_msg_len]; // ��׼���뻺����
            bzero(&strStdinBuffer, max_msg_len); // ��ջ�����

            while(strStdinBuffer[0]==0)
            {
                // �ӱ�׼�����ȡ����
                if (fgets(strStdinBuffer, max_msg_len, stdin) == NULL)
                {
                    continue;
                }
            }
            
            char strEncryBuffer[max_msg_len]; // ���ܺ�����ݻ�����
            int nLen = max_msg_len; // ���ܺ����ݵĳ���

            // �� char ����ת��Ϊ string
            string strStdin(strStdinBuffer);
            string key(pKey);

            // ��������
            string encryptedData;
            cDes.encry_operation(strStdinBuffer, string(pKey), encryptedData);
            
            // �� string ת��Ϊ char* ����
            strncpy(strEncryBuffer, encryptedData.c_str(), max_msg_len);
            //printf("after DES: %s\n",strEncryBuffer);


            // ���ͼ��ܺ�����ݵ��׽���
            if (send(nSock, strEncryBuffer, nLen, 0) != nLen)
            {
                perror("send");
            }
            else
            {
                // ����Ƿ����˳�����
                if (strncmp("quit", strStdinBuffer, 4) == 0)
                {
                    printf("Quit��\n");
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
    cin >> strIpAddr; // ���� IP ��ַ

    int nConnectSocket, nLength; //�׽����������ͳ���
    struct sockaddr_in sDestAddr; // Ŀ���ַ

    // �����׽���
    if ((nConnectSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        perror("Socket"); // ����׽��ִ���ʧ�ܣ����ӡ������Ϣ
        exit(errno); 
    }

    // ��ʼ��Ŀ���ַ�ṹ
    sDestAddr.sin_family = AF_INET; // ���õ�ַ��Ϊ IPv4
    sDestAddr.sin_port = htons(tcp_port); // ���ö˿ں�
    sDestAddr.sin_addr.s_addr = inet_addr(strIpAddr); // ���� IP ��ַ

    // ���ӵ�������
    if (connect(nConnectSocket, (struct sockaddr *) &sDestAddr, sizeof(sDestAddr)) != 0) 
    {
        perror("Connect "); // �������ʧ�ܣ����ӡ������Ϣ
        exit(errno); // �˳����򲢷��ش������
    }
    else
    {
        printf("Connect Success! \nBegin to chat...\n"); // ��ӡ���ӳɹ�����Ϣ
        SecretChat(nConnectSocket,strIpAddr,"benbenmi"); // ��ʼ����
    }

    close(nConnectSocket); // �ر��׽���
    return 0;
}

int server()
{

    int nListenSocket, nAcceptSocket;
    struct sockaddr_in sLocalAddr, sRemoteAddr;
    socklen_t nLength = sizeof(sRemoteAddr); // ����һ���������ڴ洢Զ�̵�ַ�ṹ��ĳ���

    // ���������׽���
    if ((nListenSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
    {
        perror("socket"); // ��������׽���ʧ�ܣ����ӡ������Ϣ
        exit(1);
    }

    // ��ʼ�����ص�ַ�ṹ
    memset(&sLocalAddr, 0, sizeof(sLocalAddr)); // ��սṹ��
    sLocalAddr.sin_family = AF_INET; // ���õ�ַ��Ϊ IPv4
    sLocalAddr.sin_port = htons(tcp_port); // ���ö˿ں�
    //sLocalAddr.sin_addr.s_addr = htonl(INADDR_ANY); // ���� IP ��ַΪ����������õ�ַ

    char server_ip[INET_ADDRSTRLEN];

    printf("Enter IP address: ");
    scanf("%s", server_ip);

    if(inet_pton(AF_INET, server_ip, &sLocalAddr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    // ���׽����뱾�ص�ַ��
    if (bind(nListenSocket, (struct sockaddr *) &sLocalAddr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind"); // �����ʧ�ܣ����ӡ������Ϣ
        exit(1); // �˳����򲢷��ش������
    }

    // ��ʼ�����׽���
    if (listen(nListenSocket, 5) == -1) 
    {
        perror("listen"); // �������ʧ�ܣ����ӡ������Ϣ
        exit(1); // �˳����򲢷��ش������
    }
    printf("Listening����");

    // �����������󣬲������µ��׽�������ͨ��
    nAcceptSocket = accept(nListenSocket, (struct sockaddr *) &sRemoteAddr, &nLength);
    close(nListenSocket); // �رռ����׽���

    // ��ӡ������Ϣ
    printf("server: got connection from %s, port %d, socket %d\n",
           inet_ntoa(sRemoteAddr.sin_addr), ntohs(sRemoteAddr.sin_port), nAcceptSocket);

    // ��ʼ����
    SecretChat(nAcceptSocket, inet_ntoa(sRemoteAddr.sin_addr), "benbenmi");

    close(nAcceptSocket); // �ر�ͨ���׽���
    return 0;
}



