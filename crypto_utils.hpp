#pragma once

#define CRYPTO_DEBUG 1

#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/x509.h>

/* 
 * Crypto Utils - Secure Communication Module
 * 
 * Implements:
 * - ECDH key exchange for fresh session keys (TLS-like)
 * - AES-256-GCM for symmetric encryption
 */

class CryptoSession {
private:
    EVP_PKEY* local_keypair = nullptr;
    std::vector<unsigned char> session_key;  // 32 bytes for AES-256
    std::vector<unsigned char> peer_public_key;
    bool key_established = false;
    
    static constexpr int AES_KEY_SIZE = 32;   // 256 bits
    static constexpr int GCM_IV_SIZE = 12;    // 96 bits recommended for GCM
    static constexpr int GCM_TAG_SIZE = 16;   // 128 bits

public:
    CryptoSession() {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
    }
    
    ~CryptoSession() {
        if (local_keypair) {
            EVP_PKEY_free(local_keypair);
        }
        // Securely clear session key
        if (!session_key.empty()) {
            OPENSSL_cleanse(session_key.data(), session_key.size());
        }
    }
    
    /* Generate ECDH keypair using P-256 curve */
    bool generate_keypair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_keygen(ctx, &local_keypair) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        EVP_PKEY_CTX_free(ctx);
        return true;
    }
    
    /* Get local public key as bytes (for sending to peer) */
    std::vector<unsigned char> get_public_key() const {
        if (!local_keypair) return {};
        
        size_t len = 0;
        if (EVP_PKEY_get_raw_public_key(local_keypair, nullptr, &len) <= 0) {
            // For EC keys, we need to use a different approach
            unsigned char* buf = nullptr;
            int buf_len = i2d_PUBKEY(local_keypair, &buf);
            if (buf_len <= 0) return {};
            
            std::vector<unsigned char> result(buf, buf + buf_len);
            OPENSSL_free(buf);
            return result;
        }
        
        std::vector<unsigned char> pubkey(len);
        EVP_PKEY_get_raw_public_key(local_keypair, pubkey.data(), &len);
        return pubkey;
    }
    
    /* Derive shared secret from peer's public key */
    bool derive_session_key(const std::vector<unsigned char>& peer_pubkey) {
        if (!local_keypair || peer_pubkey.empty()) return false;
        
        peer_public_key = peer_pubkey;
        
        // Parse peer's public key
        const unsigned char* p = peer_pubkey.data();
        EVP_PKEY* peer_key = d2i_PUBKEY(nullptr, &p, peer_pubkey.size());
        if (!peer_key) return false;
        
        // Create context for key derivation
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_keypair, nullptr);
        if (!ctx) {
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        // Determine shared secret length
        size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        // Derive shared secret
        std::vector<unsigned char> shared_secret(secret_len);
        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        
        // Use HKDF to derive session key from shared secret
        session_key.resize(AES_KEY_SIZE);
        EVP_PKEY_CTX* hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!hkdf_ctx) return false;
        
        if (EVP_PKEY_derive_init(hkdf_ctx) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, (const unsigned char*)"chat_session", 12) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret.data(), shared_secret.size()) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (const unsigned char*)"aes_key", 7) <= 0) {
            EVP_PKEY_CTX_free(hkdf_ctx);
            return false;
        }
        
        size_t key_len = AES_KEY_SIZE;
        if (EVP_PKEY_derive(hkdf_ctx, session_key.data(), &key_len) <= 0) {
            EVP_PKEY_CTX_free(hkdf_ctx);
            return false;
        }
        
        EVP_PKEY_CTX_free(hkdf_ctx);
        
        // Clear shared secret
        OPENSSL_cleanse(shared_secret.data(), shared_secret.size());
        
        key_established = true;
        
#if CRYPTO_DEBUG
        std::cerr << "\033[33m║\033[0m \033[35mSession Key Fingerprint:\033[0m " << get_session_key_fingerprint() << "..." << std::endl;
#endif
        
        return true;
    }
    
    /* Check if session key is established */
    bool is_established() const { return key_established; }
    
    /* Get session key fingerprint for demonstration (first 8 bytes as hex) */
    std::string get_session_key_fingerprint() const {
        if (!key_established || session_key.empty()) return "(not established)";
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        size_t show_bytes = std::min(size_t(8), session_key.size());
        for (size_t i = 0; i < show_bytes; i++) {
            oss << std::setw(2) << static_cast<int>(session_key[i]);
        }
        return oss.str();
    }
    
    /* Encrypt message using AES-256-GCM */
    std::vector<unsigned char> encrypt(const std::string& plaintext) {
        if (!key_established) return {};
        
        // Generate random IV
        std::vector<unsigned char> iv(GCM_IV_SIZE);
        if (RAND_bytes(iv.data(), GCM_IV_SIZE) != 1) return {};
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        // Encrypt
        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, ciphertext_len = 0;
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);
        
        // Get authentication tag
        std::vector<unsigned char> tag(GCM_TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Format: IV || Ciphertext || Tag
        std::vector<unsigned char> result;
        result.reserve(iv.size() + ciphertext.size() + tag.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.begin(), tag.end());
        
        return result;
    }
    
    /* Decrypt message using AES-256-GCM */
    std::string decrypt(const std::vector<unsigned char>& encrypted) {
        if (!key_established) return "";
        if (encrypted.size() < GCM_IV_SIZE + GCM_TAG_SIZE) return "";
        
        // Extract IV, ciphertext, and tag
        std::vector<unsigned char> iv(encrypted.begin(), encrypted.begin() + GCM_IV_SIZE);
        std::vector<unsigned char> tag(encrypted.end() - GCM_TAG_SIZE, encrypted.end());
        std::vector<unsigned char> ciphertext(encrypted.begin() + GCM_IV_SIZE,
                                               encrypted.end() - GCM_TAG_SIZE);
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Decrypt
        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0, plaintext_len = 0;
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len = len;
        
        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                                const_cast<unsigned char*>(tag.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        // Verify tag and finalize
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            // Authentication failed!
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }
    
    /* Reset for new connection */
    void reset() {
        if (local_keypair) {
            EVP_PKEY_free(local_keypair);
            local_keypair = nullptr;
        }
        if (!session_key.empty()) {
            OPENSSL_cleanse(session_key.data(), session_key.size());
            session_key.clear();
        }
        peer_public_key.clear();
        key_established = false;
    }
};

/* Utility functions for encoding/decoding binary data for transmission */
namespace CryptoUtils {
    /* Base64 encode for transmitting binary data over text protocol */
    inline std::string base64_encode(const std::vector<unsigned char>& data) {
        if (data.empty()) return "";
        
        size_t encoded_len = 4 * ((data.size() + 2) / 3);
        std::vector<char> encoded(encoded_len + 1);
        
        int actual_len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()),
                                          data.data(), data.size());
        
        return std::string(encoded.data(), actual_len);
    }
    
    /* Base64 decode */
    inline std::vector<unsigned char> base64_decode(const std::string& encoded) {
        if (encoded.empty()) return {};
        
        size_t decoded_len = 3 * encoded.size() / 4;
        std::vector<unsigned char> decoded(decoded_len);
        
        int actual_len = EVP_DecodeBlock(decoded.data(),
                                          reinterpret_cast<const unsigned char*>(encoded.data()),
                                          encoded.size());
        
        // Remove padding
        if (actual_len > 0) {
            if (encoded.size() >= 1 && encoded[encoded.size() - 1] == '=') actual_len--;
            if (encoded.size() >= 2 && encoded[encoded.size() - 2] == '=') actual_len--;
        }
        
        if (actual_len > 0) {
            decoded.resize(actual_len);
        } else {
            decoded.clear();
        }
        
        return decoded;
    }
}
