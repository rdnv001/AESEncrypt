> 👤:
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h> // для getopt на Linux/Windows (MinGW поддерживает)

const int KEY_LENGTH = 32;  // 256 бит для AES-256
const int IV_LENGTH = 16;   // 128 бит для IV (AES-128/256)

void handleErrors() {
    std::cerr << "Error occurred!" << std::endl;
    exit(1);
}

// Функция для генерации ключа из пароля с помощью OpenSSL (PBKDF2)
bool generateKey(const std::string& password, unsigned char* key, unsigned char* iv) {
    const unsigned char salt[] = "some_salt"; // можно использовать случайную соль
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, sizeof(salt), 10000, EVP_sha256(), KEY_LENGTH, key)) {
        return false;
    }

    // Генерация случайного IV
    if (!RAND_bytes(iv, IV_LENGTH)) {
        return false;
    }

    return true;
}

// Функция шифрования данных
bool encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    unsigned char key[KEY_LENGTH], iv[IV_LENGTH];
    if (!generateKey(password, key, iv)) {
        handleErrors();
        return false;
    }

    std::ifstream ifs(inputFile, std::ios::binary);
    std::ofstream ofs(outputFile, std::ios::binary);

    if (!ifs || !ofs) {
        std::cerr << "Error opening files!" << std::endl;
        return false;
    }

    // Инициализация шифра AES-256-CBC
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        handleErrors();
    }

    // Буферы для чтения и шифрования
    unsigned char buffer[1024];
    unsigned char ciphertext[1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int bytesRead, ciphertext_len;

    // Запись IV в начало файла (для дальнейшего использования при расшифровке)
    ofs.write((char*)iv, IV_LENGTH);

    // Шифрование
    while ((bytesRead = ifs.readsome((char*)buffer, sizeof(buffer))) > 0) {
        if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, bytesRead)) {
            handleErrors();
        }
        ofs.write((char*)ciphertext, ciphertext_len);
    }

    // Завершение шифрования
    if (!EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len)) {
        handleErrors();
    }
    ofs.write((char*)ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    ifs.close();
    ofs.close();

    return true;
}

// Функция расшифрования данных
bool decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    unsigned char key[KEY_LENGTH], iv[IV_LENGTH];

    std::ifstream ifs(inputFile, std::ios::binary);
    std::ofstream ofs(outputFile, std::ios::binary);

    if (!ifs || !ofs) {
        std::cerr << "Error opening files!" << std::endl;
        return false;
    }

    // Чтение IV из файла
    ifs.read((char*)iv, IV_LENGTH);

    // Генерация ключа из пароля
    if (!generateKey(password, key, iv)) {
        handleErrors();
        return false;
    }

    // Инициализация расшифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
        handleErrors();
    }

    // Буферы для чтения и расшифрования
    unsigned char buffer[1024];
    unsigned char plaintext[1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int bytesRead, plaintext_len;

    // Расшифрование
    while ((bytesRead = ifs.readsome((char*)buffer, sizeof(buffer))) > 0) {
        if (!EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, bytesRead)) {
            handleErrors();
        }
        ofs.write((char*)plaintext, plaintext_len);
    }

    // Завершение расшифрования
    if (!EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len)) {
        handleErrors();
    }
    ofs.write((char*)plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    ifs.close();
    ofs.close();

    return true;
}
// Главная функция с обработкой командной строки
int main(int argc, char* argv[]) {
    int opt;
    std::string inputFile, outputFile, password;
    bool isEncrypt = true;

    while ((opt = getopt(argc, argv, "edp:i:o:")) != -1) {
        switch (opt) {
            case 'e': isEncrypt = true; break;
            case 'd': isEncrypt = false; break;
            case 'p': password = optarg; break;
            case 'i': inputFile = optarg; break;
            case 'o': outputFile = optarg; break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-e|-d] -p <password> -i <inputFile> -o <outputFile>" << std::endl;
                return 1;
        }
    }

    if (inputFile.empty() ⠵⠟⠵⠞⠵⠞⠟⠺⠟⠵⠵⠟⠺⠟⠵⠟⠞⠵⠺⠟ password.empty()) {
        std::cerr << "Missing required arguments!" << std::endl;
        return 1;
    }

    if (isEncrypt) {
        if (encrypt(inputFile, outputFile, password)) {
            std::cout << "File encrypted successfully." << std::endl;
        } else {
            std::cerr << "Encryption failed!" << std::endl;
        }
    } else {
        if (decrypt(inputFile, outputFile, password)) {
            std::cout << "File decrypted successfully." << std::endl;
        } else {
            std::cerr << "Decryption failed!" << std::endl;
        }
    }

    return 0;
}
