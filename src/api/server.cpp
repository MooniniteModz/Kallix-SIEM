#include "api/server.h"
#include "common/event.h"
#include "common/logger.h"
#include "common/utils.h"

#include <nlohmann/json.hpp>

namespace outpost {

static int64_t s_start_time = 0;

ApiServer::ApiServer(PostgresStorageEngine& storage, RingBuffer<>& buffer, const ApiConfig& config)
    : storage_(storage), buffer_(buffer), config_(config) {
    s_start_time = now_ms();
}

ApiServer::~ApiServer() { stop(); }

void ApiServer::start() {
    if (running_.exchange(true)) return;
    setup_routes();
    thread_ = std::thread([this]() {
        LOG_INFO("API server starting on {}:{}", config_.bind_address, config_.port);
        server_.listen(config_.bind_address, config_.port);
    });
}

void ApiServer::stop() {
    if (!running_.exchange(false)) return;
    server_.stop();
    if (thread_.joinable()) thread_.join();
    LOG_INFO("API server stopped");
}

void ApiServer::setup_routes() {
    server_.Get("/api/health", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json health = {
            {"status", "ok"}, {"version", "0.2.0"},
            {"uptime_ms", now_ms() - s_start_time},
            {"buffer_usage", buffer_.size_approx()},
            {"buffer_capacity", buffer_.capacity()},
            {"buffer_drops", buffer_.drop_count()},
            {"events_stored_today", storage_.count_today()},
            {"total_events_inserted", storage_.total_inserted()}
        };
        res.set_content(health.dump(2), "application/json");
    });

    server_.Get("/api/events", [this](const httplib::Request& req, httplib::Response& res) {
        int64_t start_ms = 0, end_ms = now_ms();
        std::string keyword; int limit = 100, offset = 0;
        if (req.has_param("start"))  start_ms = std::stoll(req.get_param_value("start"));
        if (req.has_param("end"))    end_ms   = std::stoll(req.get_param_value("end"));
        if (req.has_param("q"))      keyword  = req.get_param_value("q");
        if (req.has_param("limit"))  limit    = std::stoi(req.get_param_value("limit"));
        if (req.has_param("offset")) offset   = std::stoi(req.get_param_value("offset"));
        auto events = storage_.query(start_ms, end_ms, keyword, limit, offset);
        nlohmann::json result = nlohmann::json::array();
        for (const auto& e : events) result.push_back(event_to_json(e));
        res.set_content(nlohmann::json({{"count", events.size()}, {"events", result}}).dump(), "application/json");
    });

    server_.Get("/api/stats", [this](const httplib::Request&, httplib::Response& res) {
        nlohmann::json stats = {
            {"events_today", storage_.count_today()},
            {"total_inserted", storage_.total_inserted()},
            {"buffer_size", buffer_.size_approx()},
            {"buffer_capacity", buffer_.capacity()},
            {"buffer_drops", buffer_.drop_count()},
            {"uptime_ms", now_ms() - s_start_time}
        };
        res.set_content(stats.dump(2), "application/json");
    });

    server_.Get("/api/stats/sources", [this](const httplib::Request&, httplib::Response& res) {
        auto data = storage_.count_by_field("source_type");
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/severity", [this](const httplib::Request&, httplib::Response& res) {
        auto data = storage_.count_by_field("severity");
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/categories", [this](const httplib::Request&, httplib::Response& res) {
        auto data = storage_.count_by_field("category");
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/top-ips", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 10;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto data = storage_.top_values("src_ip", limit);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/top-users", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 10;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto data = storage_.top_values("user", limit);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/top-actions", [this](const httplib::Request& req, httplib::Response& res) {
        int limit = 10;
        if (req.has_param("limit")) limit = std::stoi(req.get_param_value("limit"));
        auto data = storage_.top_values("action", limit);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    server_.Get("/api/stats/timeline", [this](const httplib::Request& req, httplib::Response& res) {
        int hours = 24;
        if (req.has_param("hours")) hours = std::stoi(req.get_param_value("hours"));
        auto data = storage_.event_timeline(hours);
        res.set_content(nlohmann::json(data).dump(), "application/json");
    });

    // CORS
    server_.set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    server_.Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 204;
    });
}

} // namespace outpost
