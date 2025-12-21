#include "network_utils.hpp"
#include <unistd.h>
#include <iostream>
#include <iomanip>

bool NetworkUtils::send_line(int fd, const std::string& message) {
    std::string line = message + "\n";
    ssize_t total_sent = 0;
    ssize_t len = line.length();
    
    while (total_sent < len) {
        ssize_t sent = send(fd, line.c_str() + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                case EPIPE:
                case ECONNRESET:
                    return false;
                default:
                    ERR_EXIT("send");
            }
        }
        total_sent += sent;
    }
    return true;
}

bool NetworkUtils::recv_line(int fd, std::string& out) {
    out.clear();
    char c;
    
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                default:
                    return false;
            }
        }
        else if (n == 0) { // Connection closed
            return false;
        }
        
        if (c == '\n')
            return true;
        out += c;
    }
}

bool NetworkUtils::send_encrypted(int fd, const std::string& message, CryptoSession& crypto) {
    if (!crypto.is_established()) {
        // Fallback to unencrypted if session not established
        return send_line(fd, message);
    }
    
    // Encrypt message
    std::vector<unsigned char> encrypted = crypto.encrypt(message);
    if (encrypted.empty()) {
        return false;
    }
    
    // Encode as base64 for text transmission and send with "ENC:" prefix
    std::string encoded = "ENC:" + CryptoUtils::base64_encode(encrypted);
    
#if CRYPTO_DEBUG
    std::cerr << "\n\033[35m╔══════════════════════════════════════════════════════════╗\033[0m" << std::endl;
    std::cerr << "\033[35m║\033[0m \033[1;33m🔐 ENCRYPTION DEMO (AES-256-GCM)\033[0m" << std::endl;
    std::cerr << "\033[35m╠══════════════════════════════════════════════════════════╣\033[0m" << std::endl;
    std::cerr << "\033[35m║\033[0m \033[32mPlaintext:\033[0m  " << message << std::endl;
    std::cerr << "\033[35m║\033[0m \033[31mCiphertext:\033[0m " << encoded.substr(0, 60) << "..." << std::endl;
    std::cerr << "\033[35m║\033[0m \033[36mLength:\033[0m     " << message.length() << " bytes → " << encoded.length() << " bytes" << std::endl;
    std::cerr << "\033[35m╚══════════════════════════════════════════════════════════╝\033[0m\n" << std::endl;
#endif
    
    return send_line(fd, encoded);
}

bool NetworkUtils::recv_encrypted(int fd, std::string& out, CryptoSession& crypto) {
    std::string line;
    if (!recv_line(fd, line)) {
        return false;
    }
    
    // Check if message is encrypted (has "ENC:" prefix)
    if (line.substr(0, 4) == "ENC:") {
        if (!crypto.is_established()) {
            // Cannot decrypt without session key
            out = "";
            return false;
        }
        
        // Decode and decrypt
        std::string encoded = line.substr(4);
        std::vector<unsigned char> encrypted = CryptoUtils::base64_decode(encoded);
        out = crypto.decrypt(encrypted);
        
#if CRYPTO_DEBUG
        std::cerr << "\n\033[36m╔══════════════════════════════════════════════════════════╗\033[0m" << std::endl;
        std::cerr << "\033[36m║\033[0m \033[1;33m🔓 DECRYPTION DEMO (AES-256-GCM)\033[0m" << std::endl;
        std::cerr << "\033[36m╠══════════════════════════════════════════════════════════╣\033[0m" << std::endl;
        std::cerr << "\033[36m║\033[0m \033[31mCiphertext:\033[0m " << line.substr(0, 60) << "..." << std::endl;
        std::cerr << "\033[36m║\033[0m \033[32mPlaintext:\033[0m  " << out << std::endl;
        std::cerr << "\033[36m╚══════════════════════════════════════════════════════════╝\033[0m\n" << std::endl;
#endif
        
        return !out.empty();
    }
    
    // Unencrypted message (for backward compatibility or key exchange)
    out = line;
    return true;
}

void NetworkUtils::ERR_EXIT(const char* msg) {
    std::perror(msg);
    exit(EXIT_FAILURE);
}
