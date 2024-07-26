#include"DES_func.h"

// DES 加密操作
int CDesOperate::encry_operation(string raw_text, string key, string& encry_res) {
    // 检查密钥长度是否为 8
    if (key.size() != 8) {
        cout << "error: key size isn't 8!" << endl;
        return -1;
    }

    // 将密钥转换为二进制形式
    vector<bool> bin_key = key_str2bool(key);

    // 生成子密钥
    vector<vector<bool> > sub_key = gen_subkey(bin_key);

    // 将原始文本转换为二进制形式
    vector<vector<bool> > bin_raw_text = encry_str2bool(raw_text);

    // 存储加密后的二进制密文
    vector<vector<bool> > bin_code_text;

    // 对每个文本块进行加密
    for (int i = 0; i < bin_raw_text.size(); i++) {
        vector<bool> temp_res = encry_process(bin_raw_text[i], sub_key);
        bin_code_text.push_back(temp_res);
    }

    // // 将二进制密文转换为十六进制字符串
    // encry_res = "";
    // int dec2hex[] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    //                   0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    // for (int i = 0; i < bin_code_text.size(); i++) {
    //     int letter_assign = 0;
    //     while (letter_assign < 64) {
    //         vector<bool> bin_cipher_letter(bin_code_text[i].begin() + letter_assign, 
    //                                        bin_code_text[i].begin() + letter_assign + 4);
    //         int decipher_letter_dec = binary2dec(bin_cipher_letter);
    //         encry_res += dec2hex[decipher_letter_dec] + 65;
    //         letter_assign += 4;
    //     }
    // }

    // 将二进制密文转换为十六进制字符串
    encry_res = "";
    int dec2hex[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (int i = 0; i < bin_code_text.size(); i++) {
        for (int j = 0; j < bin_code_text[i].size(); j += 4) {
            int dec_value = 8 * bin_code_text[i][j] + 4 * bin_code_text[i][j+1] +
                            2 * bin_code_text[i][j+2] + bin_code_text[i][j+3];
            encry_res += dec2hex[dec_value];
        }
    }



    //printf("test1  : %s\n", encry_res.c_str());
    return 0;
}

// DES 加密过程
vector<bool> CDesOperate::encry_process(vector<bool> input, vector<vector<bool> > sub_key) {
    // 步骤 1：初始置换 IP
    vector<bool> temp_step1 = init_replacement_IP(input, INIT_REPLACE_IP);
    vector<bool> step1_l, step1_r;
    vector<bool> temp_l, temp_r;
    vector<bool> step3;

    // 将初始置换结果分为左右两部分
    for (int i = 0; i < 32; i++) {
        temp_l.push_back(temp_step1[i]);
        temp_r.push_back(temp_step1[i + 32]);
    }
    step1_l = temp_l;
    step1_r = temp_r;

    // 步骤 2：16 次迭代
    // 每次迭代：l_i = r_(i-1)， r_i = f(r_(i-1), subkey) XOR l_(i-1)
    for (int i = 0; i < 16; i++) {
        // 计算 F 函数的结果
        vector<bool> f_func_res = f_func(step1_r, sub_key[i]);
        // 计算 XOR 结果
        vector<bool> xor_res = XOR(f_func_res, step1_l);
        step1_l = step1_r;
        step1_r = xor_res;
    }

    // 步骤 3：逆初始置换 IP
    step3 = step1_l;
    step3.insert(step3.end(), step1_r.begin(), step1_r.end());
    step3 = init_replacement_IP(step3, INVERSE_REPLACE_IP);
    return step3;
}


// 解密操作函数
int CDesOperate::decry_operation(string cipherText, string key, string& decry_res) {
    // 检查密钥长度是否为8
    if (key.size() != 8) {
        cout << "error: key size isn't 8!" << endl;
        return -1;
    }
    
    // 将密钥字符串转换为布尔向量
    vector<bool> bin_key = key_str2bool(key);
    
    // 生成子密钥
    vector< vector<bool> > sub_key = gen_subkey(bin_key);
    
    // 将密文字符串转换为布尔向量
    vector< vector<bool> > bin_code_text = decry_str2bool(cipherText); 
    
    // 存储解密后的布尔向量
    vector< vector<bool> > bin_raw_text;
    
    // 解密过程
    for (int i = 0; i < bin_code_text.size(); i++) {
        vector<bool> temp_res = decry_process(bin_code_text[i], sub_key);
        bin_raw_text.push_back(temp_res);
    }
    
    // 将解密后的布尔向量转换为字符串
    for (int i = 0; i < bin_raw_text.size(); i++) {
        string temp_res = "";
        int letter_assign = 0;
        while (letter_assign < 64) {
            // 截取每8位二进制作为一个字符
            vector<bool> cuttedBin(bin_raw_text[i].begin() + letter_assign,
                                   bin_raw_text[i].begin() + letter_assign + 8);
            temp_res += binary2dec(cuttedBin);
            letter_assign += 8;
        }
        // 添加到解密结果中
        decry_res += temp_res;
    }

    //printf("test2: %s\n", decry_res.c_str());
    return 0;
}

// 解密处理函数
vector<bool> CDesOperate:: decry_process(vector<bool> input, vector<vector<bool> > sub_key) {
    // 步骤1：初始置换 IP
    vector<bool> temp_step1 = init_replacement_IP(input, INIT_REPLACE_IP);
    vector<bool> step1_l,step1_r;
    vector<bool> temp_l, temp_r;
    vector<bool> step3;
    
    // 将初始置换后的向量分成左右两半
    for (int i = 0; i < 32; i++) {
        temp_l.push_back(temp_step1[i]);
        temp_r.push_back(temp_step1[i + 32]);
    }
    step1_l = temp_l;
    step1_r = temp_r;
    
    // 步骤2：16轮迭代
    // 每轮迭代：r_i = l_(i-1)，l_i = f(l_(i-1), subkey) XOR r_(i-1)
    for (int i = 0; i < 16; i++) {
        // F 函数的结果
        vector<bool> f_func_res = f_func(step1_l, sub_key[15 - i]); // 以15-i的方式反向选择
        vector<bool> xor_res = XOR(f_func_res, step1_r);
        step1_r = step1_l;
        step1_l = xor_res;
    }

    // 步骤3：逆初始置换 IP
    step3 = step1_l;
    step3.insert(step3.end(), step1_r.begin(), step1_r.end());
    step3 = init_replacement_IP(step3, INVERSE_REPLACE_IP);
    return step3;
}
