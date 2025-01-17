# 实验一：基于DES加密的TCP聊天程序

## 实验目的

- 掌握对称加密算法DES的基本工作原理。
- 掌握基于TCP协议的网络通信编程。
- 通过实现一个加密聊天程序，理解加密算法在实际应用中的使用。

## 实验要求

- 在Linux操作系统中，编写一个基于DES加密的TCP聊天程序。
- 程序实现全双工通信，即可以同时发送和接收消息。
- 加密过程对用户完全透明。

## 实现步骤

1. **环境搭建**：
   - 安装Linux操作系统及必要的编程工具（如gcc、make等）。

2. **DES加密算法实现**：
   - 编写DES加密和解密的函数。

3. **TCP通信实现**：
   - 使用socket编程，建立TCP连接，实现客户端和服务器端的通信。

4. **加密聊天程序**：
   - 在TCP通信的基础上，添加DES加密和解密功能，实现加密聊天。

## 运行方法

1. **编译程序**：
   ```sh
   ./server
   ```
2. **运行服务器**：
   ```sh
   make
   ```
3. **运行客户端**：
   ```sh
   ./client <server_ip_address>
   ```

## 注意事项
  - 请确保服务器和客户端在相同网络环境下运行。
  - 使用时，请先启动服务器，再启动客户端。

## 参考
  - 《现代密码学：原理与协议》
  - Linux系统编程手册
