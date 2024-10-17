#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <unistd.h> // Для getopt на Unix-системах, на Windows потребуется аналог

#define AES_KEYLEN 32
#define AES_BLOCK_SIZE 16

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

bool deriveKey(const std::string& password, unsigned char* key, unsigned char* iv) {
    const unsigned char* salt = nullptr;
    int iterations = 10000;
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, 0, iterations, EVP_sha256(), AES_KEYLEN / 8, key)) {
        return false;
    }
    memcpy(iv, key, AES_BLOCK_SIZE);  // Используем часть ключа как IV
    return true;
}

bool encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& password) {
    unsigned char key[AES_KEYLEN / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    
    if (!deriveKey(password, key, iv)) {
        std::cerr << "Error deriving key and IV" << std::endl;
        return false;
    }

    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        std::cerr << "Error opening files" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        handleErrors();
    }

    std::vector<unsigned char> buffer(1024);
    std::vector<unsigned char> ciphertext(buffer.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len;

    while (inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, buffer.data(), buffer.size())) {
            handleErrors();
        }
        outputFile.write(reinterpret_cast<char*>(ciphertext.data()), len);
    }

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data(), &len)) {
        handleErrors();
    }
    outputFile.write(reinterpret_cast<char*>(ciphertext.data()), len);

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    return true;
}

bool decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& password) {
    unsigned char key[AES_KEYLEN / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    
    if (!deriveKey(password, key, iv)) {
        std::cerr << "Error deriving key and IV" << std::endl;
        return false;
    }

    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        std::cerr << "Error opening files" << std::endl;
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        handleErrors();
    }

    std::vector<unsigned char> buffer(1024);
    std::vector<unsigned char> plaintext(buffer.size() + AES_BLOCK_SIZE);
    int len, plaintext_len;

    while (inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, buffer.data(), buffer.size())) {
            handleErrors();
        }
        outputFile.write(reinterpret_cast<char*>(plaintext.data()), len);
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data(), &len)) {
        handleErrors();
    }
    outputFile.write(reinterpret_cast<char*>(plaintext.data()), len);

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    return true;
}

int main(int argc, char *argv[]) {
    int option;
    std::string inputFilePath, outputFilePath, password;
    bool decrypt = false;

    while ((option = getopt(argc, argv, "i:o:p:d")) != -1) {
        switch (option) {
            case 'i':
                inputFilePath = optarg;
                break;
            case 'o':
                outputFilePath = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'd':
                decrypt = true;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " -i input -o output -p password [-d]" << std::endl;
                return 1;
        }
    }

    if (inputFilePath.empty() || outputFilePath.empty() || password.empty()) {
        std::cerr << "Missing required arguments" << std::endl;
        return 1;
    }

    if (decrypt) {
        if (decryptFile(inputFilePath, outputFilePath, password)) {
            std::cout << "File decrypted successfully" << std::endl;
        } else {
            std::cerr << "Error decrypting file" << std::endl;
            return 1;
        }
    } else {
        if (encryptFile(inputFilePath, outputFilePath, password)) {
            std::cout << "File encrypted successfully" << std::endl;
        } else {
            std::cerr << "Error encrypting file" << std::endl;
            return 1;
        }
    }

    return 0;
}
