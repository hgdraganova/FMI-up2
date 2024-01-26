// sha2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cmath>
#include <bitset>

// Function to perform SHA-256 hashing
std::string sha256(const std::string& message) {
    const uint32_t K[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    std::string binaryMessage;

    // Convert the message to binary
    for (char c : message) {
        std::bitset<8> binaryChar(c);
        binaryMessage += binaryChar.to_string();
    }

    // Append '1' bit to the message
    binaryMessage += '1';

    // Append '0' bits until the length is a multiple of 512 bits
    while (binaryMessage.size() % 512 != 448) {
        binaryMessage += '0';
    }

    // Append the length of the message as a 64-bit binary string
    uint64_t messageLength = message.length() * 8;
    std::bitset<64> lengthBits(messageLength);
    binaryMessage += lengthBits.to_string();

    // Process the message in 512-bit blocks
    for (size_t i = 0; i < binaryMessage.size(); i += 512) {
        std::string block = binaryMessage.substr(i, 512);

        std::vector<uint32_t> words(64, 0);

        // Break the block into 32-bit words
        for (size_t j = 0; j < 16; j++) {
            words[j] = std::stoul(block.substr(j * 32, 32), nullptr, 2);
        }

        // Extend the words
        for (size_t j = 16; j < 64; j++) {
            uint32_t s0 = (words[j - 15] >> 7 | words[j - 15] << 25) ^ (words[j - 15] >> 18 | words[j - 15] << 14) ^ (words[j - 15] >> 3);
            uint32_t s1 = (words[j - 2] >> 17 | words[j - 2] << 15) ^ (words[j - 2] >> 19 | words[j - 2] << 13) ^ (words[j - 2] >> 10);

            words[j] = words[j - 16] + s0 + words[j - 7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (size_t j = 0; j < 64; j++) {
            uint32_t S1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[j] + words[j];
            uint32_t S0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    // Combine the hash values
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << h0
        << std::hex << std::setw(8) << std::setfill('0') << h1
        << std::hex << std::setw(8) << std::setfill('0') << h2
        << std::hex << std::setw(8) << std::setfill('0') << h3
        << std::hex << std::setw(8) << std::setfill('0') << h4
        << std::hex << std::setw(8) << std::setfill('0') << h5
        << std::hex << std::setw(8) << std::setfill('0') << h6
        << std::hex << std::setw(8) << std::setfill('0') << h7;

    return ss.str();
}

// Function to save a hashed message to a file
void saveHashToFile(const std::string& hash, const std::string& filename) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << hash;
        file.close();
        std::cout << "Hashed text saved to " << filename << std::endl;
    }
    else {
        std::cerr << "Error writing to file " << filename << std::endl;
    }
}

// Function to verify a hash
bool verifyHash(const std::string& message, const std::string& hash) {
    return sha256(message) == hash;
}

// Function to get user input and hash a message
void hashMessage() {
    std::cout << "Choose an option:\n";
    std::cout << "1. Enter text manually\n";
    std::cout << "2. Read text from a file\n";
    int subChoice;
    std::cin >> subChoice;

    std::string message;

    if (subChoice == 1) {
        std::cin.ignore(); // Clear newline before reading text
        std::cout << "Enter the text to hash: ";
        getline(std::cin, message);
    }
    else if (subChoice == 2) {
        std::string filename;
        std::cout << "Enter the filename to read from: ";
        std::cin >> filename;
        std::ifstream file(filename);

        if (file.is_open()) {
            getline(file, message);
            file.close();
        }
        else {
            std::cerr << "Error opening file " << filename << std::endl;
            return;
        }
    }
    else {
        std::cerr << "Invalid choice.\n";
        return;
    }

    std::string hash = sha256(message);
    std::cout << "SHA-256 hash: " << hash << std::endl;
}

// Function to get user input and save a hash to a file
void saveHashToFileFromUserInput() {
    std::cout << "Enter the text to hash: ";
    std::string message;
    std::cin.ignore(); // Clear newline before reading text
    getline(std::cin, message);
    std::string hash = sha256(message);
    std::string filename;
    std::cout << "Enter the filename to save to: ";
    getline(std::cin, filename);
    saveHashToFile(hash, filename);
}

// Function to get user input and verify a hash
void verifyHashFromUserInput() {
    std::cout << "Enter the hash to verify: ";
    std::string hash;
    std::cin.ignore(); // Clear newline before reading hash
    getline(std::cin, hash);
    std::cout << "Enter the text to compare: ";
    std::string message;
    getline(std::cin, message);

    if (verifyHash(message, hash)) {
        std::cout << "The hash matches.\n";
    }
    else {
        std::cout << "The hash does not match.\n";
    }
}

int main() {
    int choice;
    std::cout << "Choose an option:\n";
    std::cout << "1. Hash a message\n";
    std::cout << "2. Save a hash to a file\n";
    std::cout << "3. Verify a hash\n";
    std::cin >> choice;

    switch (choice) {
    case 1:
        hashMessage();
        break;
    case 2:
        saveHashToFileFromUserInput();
        break;
    case 3:
        verifyHashFromUserInput();
        break;
    default:
        std::cerr << "Invalid choice.\n";
        return 1;
    }

    return 0;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
