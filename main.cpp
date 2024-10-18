#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>  // для getopt()

constexpr int KEY_LENGTH = 32;  // для AES-256
constexpr int BLOCK_SIZE = 16;  // размер блока AES

void display_errors() 
{
	ERR_print_errors_fp(stderr);
	std::abort();
}

// Генерация ключа из пароля с использованием PBKDF2
void generate_key_from_password(const std::string& pwd, unsigned char* k) 
{
	const unsigned char* salt = reinterpret_cast<const unsigned char*>("12345678"); // Зерно для PBKDF2
	if (PKCS5_PBKDF2_HMAC_SHA1(pwd.c_str(), pwd.size(), salt, 8, 10000, KEY_LENGTH, k) != 1) 
    {
		display_errors();
	}
}

// Чтение файла
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
 
// Запись файла
void saveFile(const std::string& fname, const std::vector<unsigned char>& data) {
	std::ofstream f(fname, std::ios::binary);
	if (!f.is_open()) {
		std::cerr << "Cannot open file: " << fname << '\n';
		std::exit(1);
	}
	f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Шифрование данных с записью IV в начало файла
std::vector<unsigned char> encrypt_with_iv(const std::vector<unsigned char>& plaintext, unsigned char* k, unsigned char* iv) 
{
	EVP_CIPHER_CTX* context = new_evp_cipher_ctx();
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

	// Добавляем IV в начало шифрованных данных
	std::vector<unsigned char> result(BLOCK_SIZE + cipherText.size());
	std::copy(iv, iv + BLOCK_SIZE, result.begin());
	std::copy(cipherText.begin(), cipherText.end(), result.begin() + BLOCK_SIZE);

	return result;
}

// Дешифрование данных с использованием IV из начала файла
std::vector<unsigned char> decrypt_with_iv(const std::vector<unsigned char>& cipherText, unsigned char* k) 
{
	unsigned char iv[BLOCK_SIZE];
	std::copy(cipherText.begin(), cipherText.begin() + BLOCK_SIZE, iv);

	std::cout << "Extracted IV: ";
	for (int i = 0; i < BLOCK_SIZE; ++i) 
    {
		std::cout << std::hex << static_cast<int>(iv[i]) << ' ';
	}
	std::cout << std::dec << '\n';  // Возврат к десятичному

	EVP_CIPHER_CTX* context = new_evp_cipher_ctx();
	if (!context) display_errors();

	if (evp_decrypt_init_ex(context, EVP_aes_256_cbc(), nullptr, k, iv) != 1) 
    {
		display_errors();
	}

	std::vector<unsigned char> plainText(cipherText.size() - BLOCK_SIZE);
	int len = 0;
	int plainLength = 0;

	if (evp_decryption_update(context, plainText.data(), &len, cipherText.data() + BLOCK_SIZE, cipherText.size() - BLOCK_SIZE) != 1) 
    {
		display_errors();
	}
	plainLength = len;

	if (complete_evp_decrypt(context, plainText.data() + len, &len) != 1) 
    {
		display_errors();
	}
	plainLength += len;

	plainText.resize(plainLength);

	EVP_CIPHER_CTX_free(context);
	return plainText;
}

// Вывод использования программы
void display_usage(const char* prog) 
{
	std::cout << "Usage: " << prog << " [-e | -d] -i <inputfile> -o <outputfile> -p <password>\n";
}

int main(int argc, char* argv[]) 
{
	int opt;
	std::string inputFilePath, outputFilePath, pwd;
	bool isEncrypt = false, isDecrypt = false;

	// Разбор аргументов командной строки
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

	// Генерация ключа из пароля
	generate_key_from_password(pwd, key);

	// Чтение данных из файла
	std::vector<unsigned char> inputData = read_file(inputFilePath);
	std::vector<unsigned char> outputData;

	if (isEncrypt) 
    {
		// Генерация случайного IV
		if (!RAND_bytes(iv, BLOCK_SIZE)) 
        {
			display_errors();
		}

		std::cout << "Generated IV: ";
		for (int i = 0; i < BLOCK_SIZE; ++i) 
        {
			std::cout << std::hex << static_cast<int>(iv[i]) << ' ';
		}
		std::cout << std::dec << '\n';  // Возврат к десятичному

		// Шифрование данных с записью IV
		outputData = encrypt_with_iv(inputData, key, iv);
	} 

    else if (isDecrypt) 
    {
		// Дешифрование данных с использованием IV из файла
		outputData = decrypt_with_iv(inputData, key);
	}

	// Запись результата в файл
	saveFile(outputFilePath, outputData);
	std::cout << "Operation " << (isEncrypt ? "encryption" : "decryption") << " completed successfully!\n";

	return 0;
}
