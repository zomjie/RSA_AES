#include "../include/rsa.h"
#include "../include/aes.h"
#include <iostream>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <fstream>
#include <cstring>
#include <iomanip>

using namespace std;

bool truncate_from_begin(const string& filename, size_t truncate_size) {
    int fd = open(filename.c_str(), O_RDWR);
    if (fd == -1) {
        cerr << "Failed to open file" << endl;
        return false;
    }

    // 获取文件大小
    off_t total_size = lseek(fd, 0, SEEK_END);
    off_t keep_size = total_size - truncate_size;

    // 将文件映射到内存
    void* mapped = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        close(fd);
        return false;
    }

    // 将需要保留的数据移动到内存映射的开始位置
    memmove(mapped, (char*)mapped + truncate_size, keep_size);

    // 解除映射
    munmap(mapped, total_size);

    // 截断文件
    if (ftruncate(fd, keep_size) == -1) {
        close(fd);
        return false;
    }

    close(fd);
    return true;
}


void Encrypt_File(MYRSA &rsa, std::string plain, std::string encrypted){
    std::cout<<"Encrypting..."<<std::endl;
    
    AES aes;
    aes.generate_key();
    std::vector<unsigned char> aes_key = aes.get_key();

    std::vector<unsigned char> cipher_key(rsa.get_block_size()+1, 0);
    size_t cipher_len;
    rsa.encrypt(aes_key.data(), AES_KEY_LEN, cipher_key.data(), cipher_len);

    std::ofstream ofs(encrypted, std::ios::binary);
    if (!ofs) {
        std::cerr << "Error: failed to open file " << encrypted << std::endl;
        return;
    }

    ofs.write(reinterpret_cast<char*>(&cipher_len), sizeof(size_t));
    ofs.write(reinterpret_cast<char*>(cipher_key.data()), cipher_len);

    ofs.close();

    aes.encrypt_file(plain, encrypted);

    std::cout<<"Encrypt successful"<<std::endl;

}

void Decrypt_File(MYRSA &rsa, std::string encrypted, std::string decrypted){
    std::cout<<"Decrypting..."<<std::endl;

    std::fstream ifs_(encrypted, std::ios::binary | std::ios::in | std::ios::out);
    size_t cipher_len_;
    std::vector<unsigned char> cipher_key_;
    ifs_.read(reinterpret_cast<char*>(&cipher_len_), sizeof(size_t));


    cipher_key_.resize(cipher_len_);
    ifs_.read(reinterpret_cast<char*>(cipher_key_.data()), cipher_len_);

    std::vector<unsigned char> aes_key(AES_KEY_LEN);
    rsa.decrypt(cipher_key_.data(), cipher_len_, aes_key.data(), AES_KEY_LEN);

    ifs_.close();

    //truncate the file
    truncate_from_begin(encrypted, sizeof(size_t) + cipher_len_);

    AES aes_decrypt;
    aes_decrypt.set_key(aes_key);
    aes_decrypt.decrypt_file(encrypted, decrypted);

    std::cout<<"Decrypt successful"<<std::endl;
    

}
int main(int argc, char* argv[]){
    if(argc!= 4){
        std::cout<<"Usage: "<<argv[0]<<" plain_file -o decrypted_file"<<std::endl;
        return 1;
    }
    std::string plain, decrypted;
    std::string encrypted;
    plain = (string)argv[1];
    encrypted = plain + ".enc";
    decrypted = (string)argv[3];
    MYRSA rsa;
    rsa.generate_keys();

    Encrypt_File(rsa, plain, encrypted);
    Decrypt_File(rsa, encrypted, decrypted);
    return 0;
}
