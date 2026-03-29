// PostgresStorageEngine — Geospatial query methods
// Split from postgres_storage_engine.cpp for maintainability

#include "storage/postgres_storage_engine.h"
#include "common/logger.h"

namespace outpost {

std::vector<PostgresStorageEngine::GeoPoint> PostgresStorageEngine::get_geo_points(
    const std::string& source_filter) {
    std::lock_guard<std::mutex> conn_lock(conn_mutex_);
    std::vector<GeoPoint> results;
    if (!conn_) return results;

    std::string sql =
        "SELECT metadata->>'latitude' AS lat, "
        "       metadata->>'longitude' AS lng, "
        "       COALESCE(metadata->>'city', metadata->>'location', src_ip) AS label, "
        "       source_type, "
        "       COALESCE(metadata->>'geo_type', 'event') AS point_type, "
        "       COALESCE(metadata->>'status', 'online') AS status, "
        "       COUNT(*) AS cnt "
        "FROM events "
        "WHERE metadata ? 'latitude' AND metadata ? 'longitude' ";

    std::vector<const char*> params;
    std::string source_val;
    if (!source_filter.empty() && source_filter != "all") {
        source_val = source_filter;
        sql += "AND source_type = $1 ";
        params.push_back(source_val.c_str());
    }

    sql += "GROUP BY lat, lng, label, source_type, point_type, status "
           "ORDER BY cnt DESC LIMIT 500;";

    PGresult* res = PQexecParams(conn_, sql.c_str(),
                                 static_cast<int>(params.size()),
                                 nullptr, params.empty() ? nullptr : params.data(),
                                 nullptr, nullptr, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG_ERROR("get_geo_points query failed: {}", PQerrorMessage(conn_));
        PQclear(res);
        return results;
    }

    int rows = PQntuples(res);
    for (int i = 0; i < rows; ++i) {
        GeoPoint pt;
        try {
            pt.latitude  = std::stod(PQgetvalue(res, i, 0));
            pt.longitude = std::stod(PQgetvalue(res, i, 1));
        } catch (...) { continue; }
        pt.label      = PQgetvalue(res, i, 2);
        pt.source     = PQgetvalue(res, i, 3);
        pt.point_type = PQgetvalue(res, i, 4);
        pt.status     = PQgetvalue(res, i, 5);
        pt.count      = std::stoll(PQgetvalue(res, i, 6));
        results.push_back(std::move(pt));
    }

    PQclear(res);
    return results;
}

} // namespace outpost
