#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;

// Функция для генерации ключей RSA
void GenerateRSAKeys(RSA::PrivateKey& privateKey, Integer& n, Integer& e, Integer& d) {
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    //params.SetPublicExponent(65537);
    params.GenerateRandomWithKeySize(rng, 2048);
    privateKey = RSA::PrivateKey(params);
    //const RSA::PublicKey& publicKey = params.GetPublicKey();
    const Integer& modulus = params.GetModulus();

    n = modulus;
    e = params.GetPublicExponent();
    d = privateKey.GetPrivateExponent();
}

// Функция для шифрования текста
std::string RSAEncrypt(const std::string& plaintext, const Integer& e, const Integer& n) {
    AutoSeededRandomPool rng;
    RSA::PublicKey publicKey;
    publicKey.Initialize(n, e);

    std::string encrypted;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

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
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    StringSource(ciphertext, true,
        new PK_DecryptorFilter(
            rng, decryptor,
            new StringSink(decrypted)
        )
    );

    return decrypted;
}

int main() {
    Integer p, q, n, e, d;
    RSA::PrivateKey privateKey;

    // Генерация ключей
    GenerateRSAKeys(privateKey, n, e, d);

    // Вывод параметров RSA
    std::cout << "Generated RSA Parameters:" << std::endl;
    std::cout << "n: " << n << std::endl;
    std::cout << "e: " << e << std::endl;
    std::cout << "d: " << d << std::endl;

    std::string plaintext;
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, plaintext);

    // Шифрование
    clock_t start_encrypt = clock();
    std::string encrypted = RSAEncrypt(plaintext, e, n);
    clock_t end_encrypt = clock();
    double elapsed_encrypt = double(end_encrypt - start_encrypt) / CLOCKS_PER_SEC;
    std::cout << "Encrypted text: " << encrypted << std::endl;
    std::cout << "Encryption Time: " << elapsed_encrypt << " seconds" << std::endl;
    //std::cout << "d (hex): " << std::hex << d << std::endl;

    // Расшифрование
    clock_t start_decrypt = clock();
    std::string decrypted = RSADecrypt(encrypted, d, n, e);
    clock_t end_decrypt = clock();
    double elapsed_decrypt = double(end_decrypt - start_decrypt) / CLOCKS_PER_SEC;
    std::cout << "Decrypted text: " << decrypted << std::endl;
    std::cout << "Decryption Time: " << elapsed_decrypt << " seconds" << std::endl;

    return 0;
}
