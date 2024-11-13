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

// Status information structure
struct DhtStatusInfo {
    std::string version;
    std::string node_id;
    std::string uptime;
    std::string listen_info;
    int port;
    int ipv4_nodes;
    int ipv4_good_nodes;
    int ipv6_nodes;
    int ipv6_good_nodes;
    int storage_entries;
    int storage_addresses;
    int ipv4_searches;
    int ipv4_searches_done;
    int ipv6_searches;
    int ipv6_searches_done;
    int announcements;
    int blocklist;
    double traffic_in;
    std::string traffic_in_rate;
    double traffic_out;
    std::string traffic_out_rate;
};

void ParseDhtStatus(const std::string& status_str, DhtStatusInfo& info);

} // namespace duckdb
