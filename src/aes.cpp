#include "../include/aes.h"
#include <fstream>
#include <iostream>
#include <cstring>

AES::AES() {
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    ctx = EVP_CIPHER_CTX_new();
}

AES::~AES() {
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(ctx);
}

void AES::generate_key() {
    if (RAND_bytes(key, sizeof(key)) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
}

void AES::set_key(const std::vector<unsigned char>& new_key) {
    if (new_key.size() != 16) {
        throw std::runtime_error("Invalid key size");
    }
    memcpy(key, new_key.data(), 16);
}

void AES::generate_iv() {
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }
}

std::vector<unsigned char> AES::get_key() const {
    return std::vector<unsigned char>(key, key + 16);
}

std::vector<unsigned char> AES::get_iv() const {
    return std::vector<unsigned char>(iv, iv + 16);
}

std::vector<unsigned char> AES::add_pkcs5_padding(const std::vector<unsigned char>& data) {
    size_t padding_size = 16 - (data.size() % 16);
    std::vector<unsigned char> padded = data;
    padded.insert(padded.end(), padding_size, padding_size);
    return padded;
}

std::vector<unsigned char> AES::remove_pkcs5_padding(const std::vector<unsigned char>& data) {
    if (data.empty()) return data;
    size_t padding_size = data.back();
    if (padding_size > 16 || padding_size == 0) {
        throw std::runtime_error("Invalid padding");
    }
    return std::vector<unsigned char>(data.begin(), data.end() - padding_size);
}

bool AES::encrypt_file(const std::string& input_file, const std::string& output_file) {
    std::ifstream in(input_file, std::ios::binary);
    std::ofstream out(output_file, std::ios::binary | std::ios::app);
    if (!in || !out) return false;

    generate_iv();
    out.write(reinterpret_cast<char*>(iv), 16);

    const size_t BUFFER_SIZE = 1024 * 1024;
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> encrypted(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int encrypted_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv)) {
        return false;
    }

    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
        std::streamsize bytes_read = in.gcount();
        
        if (bytes_read > 0) {
            std::vector<unsigned char> to_encrypt;
            if (!in) {
                to_encrypt = add_pkcs5_padding(std::vector<unsigned char>(
                    buffer.begin(), buffer.begin() + bytes_read));
            } else {
                to_encrypt = std::vector<unsigned char>(
                    buffer.begin(), buffer.begin() + bytes_read);
            }

            if (!EVP_EncryptUpdate(ctx, encrypted.data(), &encrypted_len,
                                 to_encrypt.data(), to_encrypt.size())) {
                return false;
            }

            out.write(reinterpret_cast<char*>(encrypted.data()), encrypted_len);
        }
    }

    if (!EVP_EncryptFinal_ex(ctx, encrypted.data(), &encrypted_len)) {
        return false;
    }
    
    if (encrypted_len > 0) {
        out.write(reinterpret_cast<char*>(encrypted.data()), encrypted_len);
    }

    in.close();
    out.close();
    return true;
}

bool AES::decrypt_file(const std::string& input_file, const std::string& output_file) {
    std::ifstream in(input_file, std::ios::binary);
    std::ofstream out(output_file, std::ios::binary);
    if (!in || !out) return false;

    // 读取IV
    in.read(reinterpret_cast<char*>(iv), 16);
    if (!in) return false;

    const size_t BUFFER_SIZE = 1024 * 1024;
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> decrypted(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    int decrypted_len;

    // 初始化解密上下文
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv)) {
        return false;
    }

    // 保存最后一块数据
    std::vector<unsigned char> last_block;

    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
        std::streamsize bytes_read = in.gcount();
        
        if (bytes_read > 0) {
            // 如果有上一块的数据，先写入
            if (!last_block.empty()) {
                out.write(reinterpret_cast<char*>(last_block.data()), last_block.size());
                last_block.clear();
            }

            // 解密当前块
            if (!EVP_DecryptUpdate(ctx, decrypted.data(), &decrypted_len,
                                 buffer.data(), bytes_read)) {
                return false;
            }

            // 如果这是最后一块，处理填充
            if (!in) {
                auto unpadded = remove_pkcs5_padding(std::vector<unsigned char>(
                    decrypted.begin(), decrypted.begin() + decrypted_len));
                out.write(reinterpret_cast<char*>(unpadded.data()), unpadded.size());
            } else {
                // 不是最后一块，保存起来
                last_block = std::vector<unsigned char>(
                    decrypted.begin(), decrypted.begin() + decrypted_len);
            }
        }
    }

    // 完成解密
    if (!EVP_DecryptFinal_ex(ctx, decrypted.data(), &decrypted_len)) {
        return false;
    }

    if (decrypted_len > 0) {
        out.write(reinterpret_cast<char*>(decrypted.data()), decrypted_len);
    }

    in.close();
    out.close();
    return true;
}
