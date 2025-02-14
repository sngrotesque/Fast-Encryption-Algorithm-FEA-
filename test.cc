#include "FEA.hh"

#include "FEA_CBC.cc"
#include "FEA_ECB.cc"
#include "FEA_CTR.cc"
#include "FEA_CFB.cc"
#include "FEA.cc"

#include "Counter.cc"

#include <iostream>

void print_hex(const wByte *data, wSize len, wSize num, bool newline, bool tableChar)
{
    for(wSize i = 0; i < len; ++i) {
        if(tableChar && ((i) % num == 0)) {
            printf("\t");
        }

        printf("%02x", data[i]);

        if((i + 1) % num) {
            printf(" ");
        } else {
            printf("\n");
        }
    }
    if(newline)
        printf("\n");
}

wByte *pkcs7_pad(const wByte *data, wSize &length, wU32 blockSize)
{
    if(!data) {
        return nullptr;
    }
    wU32 padLen;
    wSize totalLen;

    padLen = blockSize - length % blockSize;
    totalLen = length + padLen;

    wByte *padded = reinterpret_cast<wByte *>(malloc(totalLen));
    memcpy(padded, data, length);
    memset(padded + length, padLen, padLen);

    length = totalLen;

    return padded;
}

wByte *pkcs7_unpad(const wByte *data, wSize &length)
{
    if(!data) {
        return nullptr;
    }
    wU32 padLen = data[length - 1];
    wSize unpaddedLen = length - padLen;

    wByte *unpadded = reinterpret_cast<wByte *>(malloc(unpaddedLen));
    memcpy(unpadded, data, unpaddedLen);

    length = unpaddedLen;

    return unpadded;
}

void encrypt_with_decrypt_testing(mode xcrypt_mode)
{
    // Initialize the key and initial vector.
    wByte iv[WUK_FEA_IVLEN] = {
        0xda, 0xa3, 0x22, 0x84, 0x68, 0x31, 0x4d, 0xe7,
        0x86, 0x37, 0x19, 0x04, 0xea, 0x3f, 0x10, 0x69
    };
    wByte key[WUK_FEA_KEYLEN] = {
        0xd3, 0x9e, 0x2a, 0x33, 0x69, 0x82, 0x51, 0xa3,
        0x60, 0x31, 0x3b, 0x65, 0xb7, 0xa0, 0x64, 0xad,
        0x87, 0x12, 0xd7, 0x8d, 0x1a, 0x45, 0x03, 0x36,
        0xe9, 0xf6, 0xcc, 0x5e, 0xc9, 0xfe, 0x4e, 0x89
    };

    // Set a plain text content.
    char _p[] = {
        "hello, world.\n"
        "I'm SN-Grotesque.\n"
    };
    wByte *content = reinterpret_cast<wByte *>(_p);
    wSize length = strlen(_p);

    // Padding in plaintext (for ECB and CBC modes).
    wByte *padded = pkcs7_pad(content, length, WUK_FEA_BL);

    // Print plaintext content.
    std::cout << "Plaintext(Padded):\n";
    print_hex(padded, length, 16, true, true);

    // Initialize encryption context.
    Counter counter("this is test.", 123456);
    wU32 segment_size = 32; // Min: 8, Max: 128.
    FEA fea(key, iv, counter, segment_size);

    // Print round key
    std::cout << "Round key:\n";
    print_hex(fea.get_round_key(), WUK_FEA_KEYLEN * WUK_FEA_NR, WUK_FEA_KEYLEN, true, true);

    // Encryption
    switch (xcrypt_mode) {
        case mode::ECB:
            for (wU32 count = 0; count < length; count += WUK_FEA_BL) {
                fea.encrypt(padded + count, length, xcrypt_mode);
            }
            break;
        case mode::CBC:
            [[fallthrough]];
        case mode::CFB:
            [[fallthrough]];
        case mode::CTR:
            fea.encrypt(padded, length, xcrypt_mode);
            break;
    }

    // Print ciphertext content
    std::cout << "Ciphertext:\n";
    print_hex(padded, length, 16, true, true);

    // Decryption
    switch (xcrypt_mode) {
        case mode::ECB:
            for (wU32 count = 0; count < length; count += WUK_FEA_BL) {
                fea.decrypt(padded + count, length, xcrypt_mode);
            }
            break;
        case mode::CBC:
            [[fallthrough]];
        case mode::CFB:
            [[fallthrough]];
        case mode::CTR:
            fea.set_counter(counter);
            fea.decrypt(padded, length, xcrypt_mode);
            break;
    }

    // Print plaintext content.
    std::cout << "Plaintext(Unpadded):\n";
    wByte *unpadded = pkcs7_unpad(padded, length);
    print_hex(unpadded, length, 16, true, true);

    // Release the pointer.
    free(unpadded);
    free(padded);
}

void vulnerability_testing()
{
    // Initialize to all 0 bytes (demonstrating the strength of
    // the round key generated with the weakest key and initial vector).
    wByte key[WUK_FEA_KEYLEN]{};
    wByte iv[WUK_FEA_IVLEN]{};

    // Initialize plaintext to all 0 bytes.
    wByte content[WUK_FEA_BL]{};

    // Initialize encryption context.
    FEA fea(key, iv);

    // Print round key
    std::cout << "Round key:\n";
    print_hex(fea.get_round_key(), WUK_FEA_KEYLEN * WUK_FEA_NR, WUK_FEA_KEYLEN, true, true);

    // Print plaintext content.
    std::cout << "Plaintext(Padded):\n";
    print_hex(content, sizeof(content), 16, true, true);

    // Encryption
    fea.encrypt(content, sizeof(content), mode::ECB);

    // Print ciphertext content
    std::cout << "Ciphertext:\n";
    print_hex(content, sizeof(content), 16, true, true);

    // Decryption
    fea.decrypt(content, sizeof(content), mode::ECB);

    // Print plaintext content.
    std::cout << "Plaintext(Padded):\n";
    print_hex(content, sizeof(content), 16, true, true);
}

int main()
{
    std::cout << "\x1b[96m" << "Current mode: ECB\n" << "\x1b[0m";
    encrypt_with_decrypt_testing(mode::ECB);
    std::cout << "\x1b[96m" << "Current mode: CBC\n" << "\x1b[0m";
    encrypt_with_decrypt_testing(mode::CBC);
    std::cout << "\x1b[96m" << "Current mode: CFB\n" << "\x1b[0m";
    encrypt_with_decrypt_testing(mode::CFB);
    std::cout << "\x1b[96m" << "Current mode: CTR\n" << "\x1b[0m";
    encrypt_with_decrypt_testing(mode::CTR);

    std::cout << "\x1b[96m" << "Weak key testing...\n" << "\x1b[0m";
    vulnerability_testing();

    return 0;
}
