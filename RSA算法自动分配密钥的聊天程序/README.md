# 实验二：使用RSA算法自动分配密钥的聊天程序

## 实验目的

- 理解非对称加密算法RSA的基本工作原理。
- 掌握基于RSA算法的密钥分配和保密通信系统的设计方法。
- 在Linux操作系统中，实现基于RSA算法的编程。

## 实验要求

- 在Linux操作系统中，编写一个基于RSA算法的自动分配密钥的加密聊天程序。
- 程序应包含第三章“基于DES加密的TCP通信”中的所有功能，并在此基础上进行扩展，实现密钥自动生成及基于RSA算法的密钥共享。
- 程序实现全双工通信，加密过程对用户完全透明。

## 实现步骤

1. **环境搭建**：
   - 安装Linux操作系统及必要的编程工具（如gcc、make等）。

2. **RSA加密算法实现**：
   - 编写RSA加密和解密的函数。
   - 实现RSA密钥对的生成。

3. **TCP通信实现**：
   - 使用socket编程，建立TCP连接，实现客户端和服务器端的通信。

4. **密钥分配和加密聊天程序**：
   - 在TCP通信的基础上，添加RSA密钥分配功能。
   - 实现自动生成DES密钥并进行加密通信。

## 运行方法

1. **编译程序**：
   ```sh
   make
   ```
2. **运行服务端**：
   ```sh
   ./server
   ```
3. **运行客户端**：
   ```sh
   ./client <server_ip_address>
   ```

## 注意事项
  - 请确保服务器和客户端在相同网络环境下运行。
  - 使用时，请先启动服务器，再启动客户端。
## 参考资料
  - 《现代密码学：原理与协议》
  - Linux系统编程手册
