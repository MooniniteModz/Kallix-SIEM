#include "auth/totp.h"
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <ctime>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace outpost {

// ── Base32 (RFC 4648) ─────────────────────────────────────────────────────────

static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static std::string base32_encode(const uint8_t* data, size_t len) {
    std::string out;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < len; ++i) {
        buf = (buf << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            out += B32[(buf >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if (bits > 0) out += B32[(buf << (5 - bits)) & 0x1F];
    while (out.size() % 8) out += '=';
    return out;
}

static std::vector<uint8_t> base32_decode(const std::string& s) {
    std::vector<uint8_t> out;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=' || c == ' ') continue;
        c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
        int v = -1;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        if (v < 0) continue;
        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8) {
            out.push_back(static_cast<uint8_t>((buf >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

// ── HOTP / TOTP (RFC 4226 / RFC 6238) ────────────────────────────────────────

static uint32_t hotp(const std::vector<uint8_t>& key, uint64_t counter) {
    uint8_t msg[8];
    for (int i = 7; i >= 0; --i) { msg[i] = counter & 0xFF; counter >>= 8; }

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hlen = 0;
    HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
         msg, 8, hash, &hlen);

    int offset = hash[hlen - 1] & 0x0F;
    uint32_t code = ((hash[offset]   & 0x7F) << 24)
                  | ((hash[offset+1] & 0xFF) << 16)
                  | ((hash[offset+2] & 0xFF) <<  8)
                  |  (hash[offset+3] & 0xFF);
    return code % 1000000;
}

// ── Public API ────────────────────────────────────────────────────────────────

std::string totp_generate_secret() {
    uint8_t raw[20];
    RAND_bytes(raw, sizeof(raw));
    return base32_encode(raw, sizeof(raw));
}

std::string totp_uri(const std::string& secret,
                     const std::string& account,
                     const std::string& issuer) {
    // Percent-encode spaces and colons in display names
    auto encode = [](const std::string& s) {
        std::ostringstream o;
        for (unsigned char c : s) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o << c;
            else o << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return o.str();
    };
    return "otpauth://totp/" + encode(issuer) + "%3A" + encode(account)
         + "?secret=" + secret
         + "&issuer=" + encode(issuer)
         + "&algorithm=SHA1&digits=6&period=30";
}

bool totp_verify(const std::string& base32_secret, const std::string& code, int window) {
    if (code.size() != 6) return false;
    int input = 0;
    for (char c : code) {
        if (c < '0' || c > '9') return false;
        input = input * 10 + (c - '0');
    }
    auto key = base32_decode(base32_secret);
    if (key.empty()) return false;
    uint64_t t = static_cast<uint64_t>(std::time(nullptr)) / 30;
    for (int d = -window; d <= window; ++d) {
        if (hotp(key, t + static_cast<uint64_t>(d)) == static_cast<uint32_t>(input))
            return true;
    }
    return false;
}

std::vector<std::string> totp_generate_backup_codes() {
    static const char ALPHA[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no O/0, I/1
    std::vector<std::string> codes;
    for (int i = 0; i < 8; ++i) {
        uint8_t raw[8];
        RAND_bytes(raw, sizeof(raw));
        std::string code;
        for (int j = 0; j < 8; ++j) {
            if (j == 4) code += '-';
            code += ALPHA[raw[j] % 32];
        }
        codes.push_back(code);
    }
    return codes;
}

std::string totp_sha256(const std::string& input) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(input.data()), input.size(), hash);
    std::ostringstream o;
    for (auto b : hash) o << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return o.str();
}

} // namespace outpost
