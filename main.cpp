#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <gmpxx.h>

using namespace CryptoPP;

// Функция для проверки, что число простое
bool IsProbablePrime(const Integer& a) {
	int counter = 0;
	for (int i = 1; i <= a; i++) {
		std::cout << "Counting" << std::endl;
		if (a % i == 0) {
			std::cout << i << std::endl;
			counter++;
		}
		if (counter>=2)
			break;
	}
	if (counter <= 2)
		return true;
	else
		return false;
}
// Функция для вычисления модульного обратного числа
Integer ModuloInverse(const Integer& a, const Integer& n) {
    return EuclideanMultiplicativeInverse(a, n);
}

void GenerateRSAKeys(RSA::PrivateKey& privateKey, Integer& n, Integer& e, Integer& d) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    std::string question = " ";
    unsigned int size;
    std::cout << "Enter key size (at least 128 bits):" << std::endl; 
    std::cin >> size;
    std::cout << "Generating primes..." << std::endl;
    params.GenerateRandomWithKeySize(rng, size);
    privateKey = RSA::PrivateKey(params);
    //const RSA::PublicKey& publicKey = params.GetPublicKey();
    const Integer& modulus = params.GetModulus();
    const Integer& p = params.GetPrime1();
    const Integer& q = params.GetPrime2();

    std::cout << "p: " << p << std::endl;
    std::cout << "q: " << q << std::endl;
    
    std::cout << "Keys have generated successfully." << std::endl;
}


void InitializeRSAKeys(RSA::PrivateKey& privateKey, const Integer& p, const Integer& q) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    
    Integer u = EuclideanMultiplicativeInverse(q, p);
    
    CryptoPP::Integer n = p*q;
    const Integer& phiN = (p-1) * (q-1);
    CryptoPP::Integer e = 65537; //65537
    CryptoPP::Integer d;
    d = EuclideanMultiplicativeInverse(e, phiN);
    
    Integer dp = d % (p - 1);
    Integer dq = d % (q - 1);

    params.Initialize(n, e, d, p, q, dp, dq, u);
    privateKey = RSA::PrivateKey(params);
}

// Функция для шифрования текста
std::string RSAEncrypt(const std::string& plaintext, const Integer& e, const Integer& n) {
    AutoSeededRandomPool rng;
    RSA::PublicKey publicKey;
    publicKey.Initialize(n, e);

    std::string encrypted;
    RSAES_PKCS1v15_Encryptor encryptor(publicKey);

    StringSource(plaintext, true,
        new PK_EncryptorFilter(
            rng, encryptor,
            new StringSink(encrypted)
        )
    );

    return encrypted;
}

// Функция для расшифрования текста
std::string RSADecrypt(const std::string& ciphertext, const Integer& d, const Integer& n, const Integer& e) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.Initialize(n, e, d);
    RSA::PrivateKey privateKey(params);

    std::string decrypted;
    RSAES_PKCS1v15_Decryptor decryptor(privateKey);

    StringSource(ciphertext, true,
        new PK_DecryptorFilter(
            rng, decryptor,
            new StringSink(decrypted)
        )
    );

    return decrypted;
}

std::string ReadFile(const std::string& filename) {
    std::string fileContent;
    
    // Экземпляр FileSource для чтения из файла
    CryptoPP::FileSource file(filename.c_str(), true, new StringSink(fileContent));
    
    return fileContent;
}

void encrypt() {
    Integer p, q, n, e, d;
    RSA::PrivateKey privateKey;

    // Ввод пользователем простых чисел p и q
    std::cout << "Enter prime number p: ";
    std::cin >> p;
    std::cout << "Enter prime number q: ";
    std::cin >> q;

    // Инициализация ключей
    clock_t start_generate = clock();
    InitializeRSAKeys(privateKey, p, q);
    clock_t end_generate = clock();
    double elapsed_generate = double(end_generate - start_generate) / CLOCKS_PER_SEC;
    std::cout << "Initializing time: " << elapsed_generate << " seconds" << std::endl;

    // Обновляем значения n, e и d
    n = privateKey.GetModulus();
    e = privateKey.GetPublicExponent();
    d = privateKey.GetPrivateExponent();

    // Вывод параметров RSA
    std::cout << "Initialized RSA Parameters:" << std::endl;
    std::cout << "n: " << n << std::endl;
    std::cout << "e: " << e << std::endl;
    std::cout << "d: " << d << std::endl;

    // Запись открытого текста в переменную plaintext
    std::string plaintext;
    std::ifstream file("plain_text.txt");
    std::getline(file, plaintext);
    file.close();
    std::cout << "Plain text: " << plaintext << std::endl;

    // Шифрование
    clock_t start_encrypt = clock();
    std::string encrypted = RSAEncrypt(plaintext, e, n);
    clock_t end_encrypt = clock();
    double elapsed_encrypt = double(end_encrypt - start_encrypt) / CLOCKS_PER_SEC;
    std::cout << "Encrypted text: " << std::endl;
    std::cout << encrypted << std::endl;
    std::cout << "Encryption Time: " << elapsed_encrypt << " seconds" << std::endl;

    // Запись в файл
    std::ofstream encryption_file;
    encryption_file.open("encrypted.txt");
    encryption_file << encrypted;
    encryption_file.close();

    std::cout << "Total Time: " << double(elapsed_encrypt + elapsed_generate) << " seconds" << std::endl;
    
}

void generate() {
    Integer p, q, n, e, d;
    RSA::PrivateKey privateKey;

    // Генерация ключей
    clock_t start_generate = clock();
    GenerateRSAKeys(privateKey, n, e, d);
    clock_t end_generate = clock();
    double elapsed_generate = double(end_generate - start_generate) / CLOCKS_PER_SEC;
    std::cout << "Generating time: " << elapsed_generate << " seconds" << std::endl;

}

void decrypt() {
    Integer p, q, n, e, d;
    RSA::PrivateKey privateKey;

    // Ввод пользователем простых чисел p и q
    std::cout << "Enter number d: ";
    std::cin >> d;
    std::cout << "Enter number n: ";
    std::cin >> n;
    std::cout << "Enter number e: ";
    std::cin >> e;


    // Чтение шифр текста из файла
    std::string filename = "encrypted.txt"; 
    std::string content = ReadFile(filename);
    
    std::cout << "File content: " << filename << ":" << std::endl;
    std::cout << content << std::endl;

    // Расшифрование
    clock_t start_decrypt = clock();
    std::string decrypted = RSADecrypt(content, d, n, e);
    clock_t end_decrypt = clock();
    double elapsed_decrypt = double(end_decrypt - start_decrypt) / CLOCKS_PER_SEC;
    std::cout << "Decrypted text: " << decrypted << std::endl;
    std::cout << "Decryption Time: " << elapsed_decrypt << " seconds" << std::endl;

}

int main() {

    Integer decision;
    std::cout << "Choose what command you want to do: encrypt=1, generate=2, decrypt=3" << std::endl;
    std::cin >> decision;

    if (decision == 1) {
        encrypt();
    }

    else if(decision == 2) {
        generate();
    }

    else if(decision == 3) {
        decrypt();
    }
}
