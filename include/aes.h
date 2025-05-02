#ifndef _AES_H
#define _AES_H

#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 16

class AES {
private:
    unsigned char key[16];    // AES-128密钥
    unsigned char iv[16];     // 初始化向量
    EVP_CIPHER_CTX *ctx;     // OpenSSL EVP上下文

    std::vector<unsigned char> add_pkcs5_padding(const std::vector<unsigned char>& data);
    std::vector<unsigned char> remove_pkcs5_padding(const std::vector<unsigned char>& data);
    void generate_iv();

public:
    AES();
    ~AES();
    
    void set_key(const std::vector<unsigned char>& new_key);
    void generate_key();
    std::vector<unsigned char> get_key() const;
    std::vector<unsigned char> get_iv() const;
    
    bool encrypt_file(const std::string& input_file, const std::string& output_file);
    bool decrypt_file(const std::string& input_file, const std::string& output_file);
};

#endif
