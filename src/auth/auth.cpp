#include "auth/auth.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <vector>

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

std::string hash_password(const std::string& password, const std::string& salt) {
    std::string input = salt + password;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    return bytes_to_hex(digest, digest_len);
}

bool verify_password(const std::string& password,
                     const std::string& salt,
                     const std::string& stored_hash) {
    return hash_password(password, salt) == stored_hash;
}

std::string generate_session_token() {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    return bytes_to_hex(buf, sizeof(buf));
}

} // namespace outpost
