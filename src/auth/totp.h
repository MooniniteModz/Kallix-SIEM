#pragma once
#include <string>
#include <vector>

namespace outpost {

// Generate a 20-byte random secret, base32-encoded (160-bit, RFC 4648)
std::string totp_generate_secret();

// otpauth:// URI for QR code — scan with any authenticator app
std::string totp_uri(const std::string& base32_secret,
                     const std::string& account,
                     const std::string& issuer = "Kallix SIEM");

// Verify a 6-digit code against a base32 secret.
// window=1 allows ±30 seconds of clock skew (industry standard).
bool totp_verify(const std::string& base32_secret,
                 const std::string& code,
                 int window = 1);

// Generate 8 one-time backup codes (format "XXXX-XXXX").
// Returns plaintext codes; caller stores SHA-256 hashes.
std::vector<std::string> totp_generate_backup_codes();

// SHA-256 hex digest — used to hash/verify backup codes
std::string totp_sha256(const std::string& input);

} // namespace outpost
