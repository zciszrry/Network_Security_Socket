#include "DES_head.h"
using namespace std;

// 左循环移位函数
vector<bool> left_shift(int shift_bit, vector<bool> ls_vector) {
    shift_bit = shift_bit % ls_vector.size();
    vector<bool> res(ls_vector.size());
    for (int i = 0; i < ls_vector.size() - shift_bit; i++) {
        res[i] = ls_vector[i + shift_bit];
    }
    for (int i = 0; i < shift_bit; i++) {
        res[ls_vector.size() - shift_bit + i] = ls_vector[i];
    }
    return res;
}

// 二进制转十进制函数
int binary2dec(vector<bool> binary) {
    int res = 0, digit = 1;
    for (int i = binary.size() - 1; i >= 0; i--) {
        int temp = binary[i] ? digit : 0;
        res += temp;
        digit <<= 1;
    }
    return res;
}

// 十进制转二进制函数
vector<bool> dec2binary(int decimal, int bit) {
    vector<bool> res(bit);
    for (int i = bit - 1; i >= 0; i--) {
        res[i] = decimal & 1;
        decimal >>= 1;
    }
    return res;
}

// 异或运算函数
vector<bool> XOR(vector<bool> input1, vector<bool> input2) {
    vector<bool> output(input1.size());
    for (int i = 0; i < input1.size(); i++) {
        output[i] = input1[i] ^ input2[i];
    }
    return output;
}

// 初始化置换(IP)和逆置换(IP)
vector<bool> CDesOperate::init_replacement_IP(vector<bool> input, int type) {
    const int* pc_table = (type == INIT_REPLACE_IP) ? init_rep_IP : inverse_init_rep_ip;
    vector<bool> result(64);
    for (int i = 0; i < 64; i++) {
        result[i] = input[pc_table[i] - 1];
    }
    return result;
}

// 原始数据转换为二进制
vector<vector<bool> > CDesOperate::encry_str2bool(string text) {
    vector<vector<bool> > bin_text;
    int group_num = text.size() / 8;
    for (int i = 0; i < group_num; i++) {
        vector<bool> temp_bin;
        for (int j = 0; j < 8; j++) {
            temp_bin.insert(temp_bin.end(), dec2binary(text[i * 8 + j], 8).begin(), dec2binary(text[i * 8 + j], 8).end());
        }
        bin_text.push_back(temp_bin);
    }
    return bin_text;
}

// 密文数据转换为二进制
vector<vector<bool> > CDesOperate::decry_str2bool(string text) {
    vector<vector<bool> > bin_text;
    int group_num = text.size() / 16;
    for (int i = 0; i < group_num; i++) {
        vector<bool> temp_bin;
        for (int j = 0; j < 16; j++) {
            temp_bin.insert(temp_bin.end(), dec2binary(text[i * 16 + j] - 65, 4).begin(), dec2binary(text[i * 16 + j] - 65, 4).end());
        }
        bin_text.push_back(temp_bin);
    }
    return bin_text;
}

// 密钥字符串转换为二进制
vector<bool> CDesOperate::key_str2bool(string key) {
    vector<bool> result;
    for (int i = 0; i < key.size(); i++) {
        vector<bool> temp_res = dec2binary(key[i], 8);
        temp_res = left_shift(1, temp_res);
        result.insert(result.end(), temp_res.begin(), temp_res.end());
    }
    return result;
}

// F 函数：E 盒、密钥加、选择压缩、替换 P
vector<bool> CDesOperate::f_func(vector<bool> input, vector<bool> key) {
    vector<bool> e_box_output, key_added_output, select_comp_output;
    e_box_output = E_Box(input);
    key_added_output = XOR(e_box_output, key);
    select_comp_output = select_comp_operation(key_added_output);
    return replace_operation(select_comp_output);
}

// 步骤 1：扩展置换(E 盒)
vector<bool> CDesOperate::E_Box(vector<bool> input) {
    vector<bool> e_box_output(48);
    for (int i = 0; i < 48; i++) {
        e_box_output[i] = input[des_E_box[i] - 1];
    }
    return e_box_output;
}

// 步骤 2：密钥加
vector<bool> CDesOperate::key_add(vector<bool> input, vector<bool> key) {
    return XOR(input, key);
}

// 步骤 3：选择压缩运算
vector<bool> CDesOperate::select_comp_operation(vector<bool> input) {
    vector<bool> res;
    for (int i = 0; i < 8; i++) {
        vector<bool> temp_group(input.begin() + i * 6, input.begin() + (i + 1) * 6);
        int temp_int = des_S_box[i][binary2dec(temp_group)];
        res.insert(res.end(), dec2binary(temp_int, 4).begin(), dec2binary(temp_int, 4).end());
    }
    return res;
}

// 步骤 4：替换 P 操作
vector<bool> CDesOperate::replace_operation(vector<bool> input) {
    vector<bool> result(32);
    for (int i = 0; i < 32; i++) {
        result[i] = input[rep_P[i] - 1];
    }
    return result;
}

// 生成 16 个子密钥
vector<vector<bool> > CDesOperate::gen_subkey(vector<bool> init_key) {
    // 生成奇偶校验位
    for (int i = 0; i < 8; i++) {
        int cnt = 0;
        for (int j = 0; j < 7; j++) {
            if (init_key[i * 8 + j]) {
                cnt++;
            }
        }
        if (cnt % 2 == 0) {
            init_key[i * 8 + 7] = true;
        } else {
            init_key[i * 8 + 7] = false;
        }
    }

    // 步骤 1：置换选择(PC-1)
    vector<vector<bool> > key_PC1(2);
    for (int i = 0; i < 28; i++) {
        key_PC1[0].push_back(init_key[key_PC_1[i] - 1]);
        key_PC1[1].push_back(init_key[key_PC_2[i] - 1]);
    }

    // 步骤 2：左循环移位
    vector<vector<bool> > key_left_shift;
    for (int i = 0; i < 16; i++) {
        key_PC1[0] = left_shift(left_shift_table[i], key_PC1[0]);
        key_PC1[1] = left_shift(left_shift_table[i], key_PC1[1]);
        vector<bool> temp_key_ls;
        temp_key_ls.insert(temp_key_ls.end(), key_PC1[0].begin(), key_PC1[0].end());
        temp_key_ls.insert(temp_key_ls.end(), key_PC1[1].begin(), key_PC1[1].end());
        key_left_shift.push_back(temp_key_ls);
    }

    // 步骤 3：置换选择
    vector<vector<bool> > key_PC2;
    for (int i = 0; i < 16; i++) {
        vector<bool> temp_key_PC2;
        for (int j = 0; j < 48; j++) {
            temp_key_PC2.push_back(key_left_shift[i][key_choose[j] - 1]);
        }
        key_PC2.push_back(temp_key_PC2);
    }
    return key_PC2;
}
