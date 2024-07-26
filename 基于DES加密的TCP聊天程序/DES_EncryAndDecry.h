#include"DES_func.h"

// DES ���ܲ���
int CDesOperate::encry_operation(string raw_text, string key, string& encry_res) {
    // �����Կ�����Ƿ�Ϊ 8
    if (key.size() != 8) {
        cout << "error: key size isn't 8!" << endl;
        return -1;
    }

    // ����Կת��Ϊ��������ʽ
    vector<bool> bin_key = key_str2bool(key);

    // ��������Կ
    vector<vector<bool> > sub_key = gen_subkey(bin_key);

    // ��ԭʼ�ı�ת��Ϊ��������ʽ
    vector<vector<bool> > bin_raw_text = encry_str2bool(raw_text);

    // �洢���ܺ�Ķ���������
    vector<vector<bool> > bin_code_text;

    // ��ÿ���ı�����м���
    for (int i = 0; i < bin_raw_text.size(); i++) {
        vector<bool> temp_res = encry_process(bin_raw_text[i], sub_key);
        bin_code_text.push_back(temp_res);
    }

    // // ������������ת��Ϊʮ�������ַ���
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

    // ������������ת��Ϊʮ�������ַ���
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

// DES ���ܹ���
vector<bool> CDesOperate::encry_process(vector<bool> input, vector<vector<bool> > sub_key) {
    // ���� 1����ʼ�û� IP
    vector<bool> temp_step1 = init_replacement_IP(input, INIT_REPLACE_IP);
    vector<bool> step1_l, step1_r;
    vector<bool> temp_l, temp_r;
    vector<bool> step3;

    // ����ʼ�û������Ϊ����������
    for (int i = 0; i < 32; i++) {
        temp_l.push_back(temp_step1[i]);
        temp_r.push_back(temp_step1[i + 32]);
    }
    step1_l = temp_l;
    step1_r = temp_r;

    // ���� 2��16 �ε���
    // ÿ�ε�����l_i = r_(i-1)�� r_i = f(r_(i-1), subkey) XOR l_(i-1)
    for (int i = 0; i < 16; i++) {
        // ���� F �����Ľ��
        vector<bool> f_func_res = f_func(step1_r, sub_key[i]);
        // ���� XOR ���
        vector<bool> xor_res = XOR(f_func_res, step1_l);
        step1_l = step1_r;
        step1_r = xor_res;
    }

    // ���� 3�����ʼ�û� IP
    step3 = step1_l;
    step3.insert(step3.end(), step1_r.begin(), step1_r.end());
    step3 = init_replacement_IP(step3, INVERSE_REPLACE_IP);
    return step3;
}


// ���ܲ�������
int CDesOperate::decry_operation(string cipherText, string key, string& decry_res) {
    // �����Կ�����Ƿ�Ϊ8
    if (key.size() != 8) {
        cout << "error: key size isn't 8!" << endl;
        return -1;
    }
    
    // ����Կ�ַ���ת��Ϊ��������
    vector<bool> bin_key = key_str2bool(key);
    
    // ��������Կ
    vector< vector<bool> > sub_key = gen_subkey(bin_key);
    
    // �������ַ���ת��Ϊ��������
    vector< vector<bool> > bin_code_text = decry_str2bool(cipherText); 
    
    // �洢���ܺ�Ĳ�������
    vector< vector<bool> > bin_raw_text;
    
    // ���ܹ���
    for (int i = 0; i < bin_code_text.size(); i++) {
        vector<bool> temp_res = decry_process(bin_code_text[i], sub_key);
        bin_raw_text.push_back(temp_res);
    }
    
    // �����ܺ�Ĳ�������ת��Ϊ�ַ���
    for (int i = 0; i < bin_raw_text.size(); i++) {
        string temp_res = "";
        int letter_assign = 0;
        while (letter_assign < 64) {
            // ��ȡÿ8λ��������Ϊһ���ַ�
            vector<bool> cuttedBin(bin_raw_text[i].begin() + letter_assign,
                                   bin_raw_text[i].begin() + letter_assign + 8);
            temp_res += binary2dec(cuttedBin);
            letter_assign += 8;
        }
        // ��ӵ����ܽ����
        decry_res += temp_res;
    }

    //printf("test2: %s\n", decry_res.c_str());
    return 0;
}

// ���ܴ�����
vector<bool> CDesOperate:: decry_process(vector<bool> input, vector<vector<bool> > sub_key) {
    // ����1����ʼ�û� IP
    vector<bool> temp_step1 = init_replacement_IP(input, INIT_REPLACE_IP);
    vector<bool> step1_l,step1_r;
    vector<bool> temp_l, temp_r;
    vector<bool> step3;
    
    // ����ʼ�û���������ֳ���������
    for (int i = 0; i < 32; i++) {
        temp_l.push_back(temp_step1[i]);
        temp_r.push_back(temp_step1[i + 32]);
    }
    step1_l = temp_l;
    step1_r = temp_r;
    
    // ����2��16�ֵ���
    // ÿ�ֵ�����r_i = l_(i-1)��l_i = f(l_(i-1), subkey) XOR r_(i-1)
    for (int i = 0; i < 16; i++) {
        // F �����Ľ��
        vector<bool> f_func_res = f_func(step1_l, sub_key[15 - i]); // ��15-i�ķ�ʽ����ѡ��
        vector<bool> xor_res = XOR(f_func_res, step1_r);
        step1_r = step1_l;
        step1_l = xor_res;
    }

    // ����3�����ʼ�û� IP
    step3 = step1_l;
    step3.insert(step3.end(), step1_r.begin(), step1_r.end());
    step3 = init_replacement_IP(step3, INVERSE_REPLACE_IP);
    return step3;
}
