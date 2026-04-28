// Minimal SMTP client — supports plaintext and SMTPS (SSL from connect).
// Used exclusively for password-reset emails; not a general mail library.

#include "auth/smtp.h"
#include "common/logger.h"

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <algorithm>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

namespace outpost {

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::string b64_encode(const std::string& input) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

static int tcp_connect(const std::string& host, int port) {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
        return -1;

    int sock = -1;
    for (auto* p = res; p; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;

        // 10-second timeouts
        struct timeval tv{ 10, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

// Read until we see a line that starts with "DDD " (final SMTP response line).
static std::string read_response(int sock) {
    std::string out;
    char buf[512];
    while (true) {
        int n = ::recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        out += buf;
        // Find last complete line; SMTP final line has "DDD " (space after code)
        auto pos = out.rfind('\n');
        size_t ls = (pos == std::string::npos || pos == 0)
                        ? 0
                        : out.rfind('\n', pos - 1) + 1;
        if (out.size() > ls + 3 && out[ls + 3] == ' ') break;
        if (pos == std::string::npos && out.size() >= 4 && out[3] == ' ') break;
    }
    return out;
}

static int response_code(const std::string& r) {
    if (r.size() < 3) return 0;
    try { return std::stoi(r.substr(0, 3)); } catch (...) { return 0; }
}

// ── Main entry point ─────────────────────────────────────────────────────────

bool send_email(const SmtpConfig& cfg,
                const std::string& to,
                const std::string& subject,
                const std::string& body_text) {
    if (!cfg.enabled || cfg.host.empty() || to.empty()) {
        LOG_DEBUG("SMTP: skipped (not configured)");
        return false;
    }

    int sock = tcp_connect(cfg.host, cfg.port);
    if (sock < 0) {
        LOG_ERROR("SMTP: cannot connect to {}:{}", cfg.host, cfg.port);
        return false;
    }

    // ── SSL wrapper (SMTPS) ─────────────────────────────────────────────
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSL_CTX* ssl_ctx = nullptr;
    SSL*     ssl_con = nullptr;

    auto ssl_write = [&](const std::string& s) {
        SSL_write(ssl_con, s.c_str(), static_cast<int>(s.size()));
    };
    auto ssl_read = [&]() -> std::string {
        char buf[4096]{};
        int n = SSL_read(ssl_con, buf, sizeof(buf) - 1);
        return (n > 0) ? std::string(buf, n) : std::string{};
    };

    if (cfg.use_ssl) {
        SSL_library_init();
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            ::close(sock);
            LOG_ERROR("SMTP: SSL_CTX_new failed");
            return false;
        }
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
        ssl_con = SSL_new(ssl_ctx);
        SSL_set_fd(ssl_con, sock);
        if (SSL_connect(ssl_con) != 1) {
            SSL_free(ssl_con); SSL_CTX_free(ssl_ctx);
            ::close(sock);
            LOG_ERROR("SMTP: SSL handshake failed");
            return false;
        }
    }

    // Unified read/write lambdas
    auto smtp_write = [&](const std::string& s) {
        if (cfg.use_ssl) ssl_write(s);
        else ::send(sock, s.c_str(), s.size(), 0);
    };
    auto smtp_read = [&]() -> std::string {
        if (cfg.use_ssl) return ssl_read();
        return read_response(sock);
    };
#else
    auto smtp_write = [&](const std::string& s) {
        ::send(sock, s.c_str(), s.size(), 0);
    };
    auto smtp_read = [&]() -> std::string {
        return read_response(sock);
    };
    if (cfg.use_ssl) {
        LOG_ERROR("SMTP: use_ssl=true but built without OpenSSL support — refusing to send credentials over plaintext");
        ::close(sock);
        return false;
    }
#endif

    auto check = [&](int expected, const std::string& cmd) -> bool {
        smtp_write(cmd + "\r\n");
        auto r = smtp_read();
        if (response_code(r) != expected) {
            LOG_WARN("SMTP: '{}' got unexpected response: {}", cmd.substr(0, 20),
                     r.substr(0, std::min(r.size(), size_t(80))));
            return false;
        }
        return true;
    };

    bool ok = false;
    do {
        // Greeting
        auto greeting = smtp_read();
        if (response_code(greeting) != 220) break;

        // EHLO
        smtp_write("EHLO " + cfg.ehlo_hostname + "\r\n");
        auto ehlo_resp = smtp_read();
        bool has_auth = (ehlo_resp.find("AUTH") != std::string::npos);

        // AUTH LOGIN (only if credentials provided and server supports it)
        if (!cfg.username.empty() && has_auth) {
            if (!check(334, "AUTH LOGIN")) break;
            if (!check(334, b64_encode(cfg.username))) break;
            smtp_write(b64_encode(cfg.password) + "\r\n");
            auto auth_resp = smtp_read();
            if (response_code(auth_resp) != 235) {
                LOG_WARN("SMTP: AUTH LOGIN failed: {}",
                         auth_resp.substr(0, std::min(auth_resp.size(), size_t(80))));
                // Fall through — some relays don't need auth
            }
        }

        // Envelope
        std::string from_addr = cfg.from;
        if (!check(250, "MAIL FROM:<" + from_addr + ">")) break;
        if (!check(250, "RCPT TO:<" + to + ">")) break;

        // Message
        smtp_write("DATA\r\n");
        auto data_resp = smtp_read();
        if (response_code(data_resp) != 354) break;

        std::string display_name = cfg.from_name.empty() ? "Kallix SIEM" : cfg.from_name;
        std::ostringstream msg;
        msg << "From: " << display_name << " <" << cfg.from << ">\r\n"
            << "To: <" << to << ">\r\n"
            << "Subject: " << subject << "\r\n"
            << "MIME-Version: 1.0\r\n"
            << "Content-Type: text/plain; charset=UTF-8\r\n"
            << "\r\n"
            << body_text << "\r\n"
            << ".\r\n";
        smtp_write(msg.str());

        auto send_resp = smtp_read();
        if (response_code(send_resp) / 100 != 2) {
            LOG_WARN("SMTP: DATA send failed: {}",
                     send_resp.substr(0, std::min(send_resp.size(), size_t(80))));
            break;
        }

        smtp_write("QUIT\r\n");
        ok = true;
    } while (false);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (ssl_con) { SSL_shutdown(ssl_con); SSL_free(ssl_con); }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
#endif
    ::close(sock);

    if (ok) LOG_INFO("SMTP: password reset email sent to {}", to);
    return ok;
}

} // namespace outpost