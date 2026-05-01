#include "auth/auth.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>

namespace outpost {

static std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string generate_salt() {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    return bytes_to_hex(buf, sizeof(buf));
}

// PBKDF2-HMAC-SHA256 with 100,000 iterations (OWASP recommended minimum)
static constexpr int PBKDF2_ITERATIONS = 100000;
static constexpr int PBKDF2_KEY_LEN    = 32;

std::string hash_password(const std::string& password, const std::string& salt) {
    unsigned char derived[PBKDF2_KEY_LEN];

    PKCS5_PBKDF2_HMAC(
        password.c_str(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.c_str()),
        static_cast<int>(salt.size()),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        PBKDF2_KEY_LEN,
        derived
    );

    return bytes_to_hex(derived, PBKDF2_KEY_LEN);
}

bool verify_password(const std::string& password,
                     const std::string& salt,
                     const std::string& stored_hash) {
    std::string computed = hash_password(password, salt);

    // Constant-time comparison to prevent timing side-channel attacks
    if (computed.size() != stored_hash.size()) return false;
    return CRYPTO_memcmp(computed.data(), stored_hash.data(), computed.size()) == 0;
}

std::string generate_session_token() {
    // Use OpenSSL CSPRNG (already was using RAND_bytes — confirmed secure)
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    return bytes_to_hex(buf, sizeof(buf));
}

std::string sha256_hex(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    return bytes_to_hex(hash, hash_len);
}

std::string validate_password_policy(const std::string& password, const AuthConfig& config) {
    if (static_cast<int>(password.size()) < config.min_password_length) {
        return "Password must be at least " + std::to_string(config.min_password_length) + " characters";
    }
    if (password.size() > 128) {
        return "Password must not exceed 128 characters";
    }
    if (config.require_uppercase &&
        std::none_of(password.begin(), password.end(), ::isupper)) {
        return "Password must contain at least one uppercase letter";
    }
    if (config.require_lowercase &&
        std::none_of(password.begin(), password.end(), ::islower)) {
        return "Password must contain at least one lowercase letter";
    }
    if (config.require_digit &&
        std::none_of(password.begin(), password.end(), ::isdigit)) {
        return "Password must contain at least one digit";
    }
    if (config.require_special) {
        bool has_special = std::any_of(password.begin(), password.end(),
            [](char c) { return !std::isalnum(static_cast<unsigned char>(c)); });
        if (!has_special) {
            return "Password must contain at least one special character";
        }
    }

    // Check for common weak patterns
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    static const std::vector<std::string> banned = {
        "password", "12345678", "qwerty", "admin", "outpost", "letmein",
        "welcome", "monkey", "dragon", "master", "login"
    };
    for (const auto& word : banned) {
        if (lower.find(word) != std::string::npos) {
            return "Password contains a common word or pattern that is not allowed";
        }
    }

    return "";  // empty = passes policy
}

std::string generate_temp_password() {
    // Build a password that always meets policy: upper + lower + digit + special + random fill
    static const char uppers[]  = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    static const char lowers[]  = "abcdefghjkmnpqrstuvwxyz";
    static const char digits[]  = "23456789";
    static const char specials[] = "!@#$%";
    static const char pool[]    = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%";

    unsigned char buf[16];
    RAND_bytes(buf, sizeof(buf));

    std::string pw;
    pw += uppers [buf[0]  % (sizeof(uppers)  - 1)];
    pw += uppers [buf[1]  % (sizeof(uppers)  - 1)];
    pw += lowers [buf[2]  % (sizeof(lowers)  - 1)];
    pw += lowers [buf[3]  % (sizeof(lowers)  - 1)];
    pw += digits [buf[4]  % (sizeof(digits)  - 1)];
    pw += digits [buf[5]  % (sizeof(digits)  - 1)];
    pw += specials[buf[6] % (sizeof(specials) - 1)];
    for (int i = 7; i < 15; i++)
        pw += pool[buf[i] % (sizeof(pool) - 1)];

    // Shuffle using Fisher-Yates with random bytes
    unsigned char shuf[15];
    RAND_bytes(shuf, sizeof(shuf));
    for (int i = static_cast<int>(pw.size()) - 1; i > 0; i--)
        std::swap(pw[i], pw[shuf[i] % (i + 1)]);

    return pw;
}

} // namespace outpost
