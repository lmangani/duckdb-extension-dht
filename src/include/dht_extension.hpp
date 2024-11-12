#pragma once

#include "duckdb.hpp"

namespace duckdb {

class DhtExtension : public Extension {
public:
	void Load(DuckDB &db) override;
	std::string Name() override;
        std::string Version() const override;
};

// Helper struct for search results
struct DHTSearchResult {
    std::string info_hash;
    std::string peer_address;
    int32_t port;
};

// Helper struct for announcements
struct DHTAnnouncement {
    std::string info_hash;
    int32_t port;
};

} // namespace duckdb
