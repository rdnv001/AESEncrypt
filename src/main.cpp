/**
 * @file main.cpp
 * @brief Программа для шифрования и дешифрования файлов с использованием AES-256 и IV, сгенерированного случайным образом.
 * 
 * Используются библиотеки OpenSSL для криптографических операций и getopt для обработки аргументов командной строки.
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>  // для getopt()

constexpr int KEY_LENGTH = 32;  ///< Длина ключа для AES-256.
constexpr int BLOCK_SIZE = 16;  ///< Размер блока для AES.

/**
 * @brief Вывод ошибок OpenSSL в stderr и завершение программы.
 */
void display_errors() 
{
    ERR_print_errors_fp(stderr);
    std::abort();
}

/**
 * @brief Генерация ключа из пароля с использованием PBKDF2 и хэша SHA1.
 * 
 * @param[in] pwd Пароль, который используется для генерации ключа.
 * @param[out] k Буфер для сохранения сгенерированного ключа длиной KEY_LENGTH.
 */
void generate_key_from_password(const std::string& pwd, unsigned char* k) 
{
    const unsigned char* salt = reinterpret_cast<const unsigned char*>("12345678");  ///< Зерно для PBKDF2.
    if (PKCS5_PBKDF2_HMAC_SHA1(pwd.c_str(), pwd.size(), salt, 8, 10000, KEY_LENGTH, k) != 1) 
    {
        display_errors();
    }
}

/**
 * @brief Чтение данных из файла в бинарном режиме.
 * 
 * @param[in] fname Имя файла для чтения.
 * @return Вектор данных, прочитанных из файла.
 */
std::vector<unsigned char> read_file(const std::string& fname) 
{
    std::ifstream f(fname, std::ios::binary);
    if (!f.is_open()) 
    {
        std::cerr << "Cannot open file: " << fname << '\n';
        std::exit(1);
    }
    
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

/**
 * @brief Запись данных в файл в бинарном режиме.
 * 
 * @param[in] fname Имя файла для записи.
 * @param[in] data Данные для записи в файл.
 */
void saveFile(const std::string& fname, const std::vector<unsigned char>& data) 
{
    std::ofstream f(fname, std::ios::binary);
    if (!f.is_open()) 
    {
        std::cerr << "Cannot open file: " << fname << '\n';
        std::exit(1);
    }
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

/**
 * @brief Шифрование данных с использованием AES-256 и записью IV в начало зашифрованного файла.
 * 
 * @param[in] plaintext Открытый текст, который нужно зашифровать.
 * @param[in] k Ключ для шифрования.
 * @param[in] iv Инициализационный вектор (IV) для шифрования.
 * @return Вектор с зашифрованными данными, включая IV в начале.
 */
std::vector<unsigned char> encrypt_with_iv(const std::vector<unsigned char>& plaintext, unsigned char* k, unsigned char* iv) 
{
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) display_errors();

    if (EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), nullptr, k, iv) != 1) 
    {
        display_errors();
    }

    std::vector<unsigned char> cipherText(plaintext.size() + BLOCK_SIZE);
    int len = 0;
    int encrypted_data_length = 0;

    if (EVP_EncryptUpdate(context, cipherText.data(), &len, plaintext.data(), plaintext.size()) != 1) 
    {
        display_errors();
    }
    encrypted_data_length = len;

    if (EVP_EncryptFinal_ex(context, cipherText.data() + len, &len) != 1) 
    {
        display_errors();
    }

    encrypted_data_length += len;
    cipherText.resize(encrypted_data_length);

    EVP_CIPHER_CTX_free(context);

    std::vector<unsigned char> result(BLOCK_SIZE + cipherText.size());
    std::copy(iv, iv + BLOCK_SIZE, result.begin());
    std::copy(cipherText.begin(), cipherText.end(), result.begin() + BLOCK_SIZE);

    return result;
}

/**
 * @brief Дешифрование данных с использованием AES-256 и IV, который хранится в начале файла.
 * 
 * @param[in] cipherText Зашифрованные данные, включая IV.
 * @param[in] k Ключ для дешифрования.
 * @return Вектор с расшифрованными данными (открытым текстом).
 */
std::vector<unsigned char> decrypt_with_iv(const std::vector<unsigned char>& cipherText, unsigned char* k) 
{
    unsigned char iv[BLOCK_SIZE];
    std::copy(cipherText.begin(), cipherText.begin() + BLOCK_SIZE, iv);

    std::cout << "Extracted IV: ";
    for (int i = 0; i < BLOCK_SIZE; ++i) 
    {
        std::cout << std::hex << static_cast<int>(iv[i]) << ' ';
    }
    std::cout << std::dec << '\n';

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) display_errors();

    if (EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), nullptr, k, iv) != 1) 
    {
        display_errors();
    }

    std::vector<unsigned char> plainText(cipherText.size() - BLOCK_SIZE);
    int len = 0;
    int plainLength = 0;

    if (EVP_DecryptUpdate(context, plainText.data(), &len, cipherText.data() + BLOCK_SIZE, cipherText.size() - BLOCK_SIZE) != 1) 
    {
        display_errors();
    }
    plainLength = len;

    if (EVP_DecryptFinal_ex(context, plainText.data() + len, &len) != 1) 
    {
        display_errors();
    }
    plainLength += len;

    plainText.resize(plainLength);

    EVP_CIPHER_CTX_free(context);
    return plainText;
}

/**
 * @brief Вывод инструкции по использованию программы.
 * 
 * @param[in] prog Имя программы.
 */
void display_usage(const char* prog) 
{
    std::cout << "Usage: " << prog << " [-e | -d] -i <inputfile> -o <outputfile> -p <password>\n";
}

/**
 * @brief Главная функция программы. Разбирает аргументы командной строки и запускает процесс шифрования/дешифрования.
 * 
 * @param[in] argc Количество аргументов.
 * @param[in] argv Массив аргументов командной строки.
 * @return Код завершения программы.
 */
int main(int argc, char* argv[]) 
{
    int opt;
    std::string inputFilePath, outputFilePath, pwd;
    bool isEncrypt = false, isDecrypt = false;

    while ((opt = getopt(argc, argv, "edi:o:p:")) != -1) 
    {
        switch (opt) {
            case 'e': isEncrypt = true; break;
            case 'd': isDecrypt = true; break;
            case 'i': inputFilePath = optarg; break;
            case 'o': outputFilePath = optarg; break;
            case 'p': pwd = optarg; break;
            default: display_usage(argv[0]); return 1;
        }
    }

    if ((isEncrypt && isDecrypt) || (!isEncrypt && !isDecrypt) || inputFilePath.empty() || outputFilePath.empty() || pwd.empty()) 
    {
        display_usage(argv[0]);
        return 1;
    }

    unsigned char key[KEY_LENGTH];
    unsigned char iv[BLOCK_SIZE];

    generate_key_from_password(pwd, key);

    std::vector<unsigned char> inputData = read_file(inputFilePath);
    std::vector<unsigned char> outputData;

    if (isEncrypt) 
    {
        if (!RAND_bytes(iv, BLOCK_SIZE)) 
        {
            display_errors();
        }

        std::cout << "Generated IV: ";
        for (int i = 0; i < BLOCK_SIZE; ++i) 
        {
            std::cout << std::hex << static_cast<int>(iv[i]) << ' ';
        }
        std::cout << std::dec << '\n';

        outputData = encrypt_with_iv(inputData, key, iv);
    } 
    else if (isDecrypt) 
    {
        outputData = decrypt_with_iv(inputData, key);
    }

    saveFile(outputFilePath, outputData);
    std::cout << "Operation " << (isEncrypt ? "encryption" : "decryption") << " completed successfully!\n";

    return 0;
}
