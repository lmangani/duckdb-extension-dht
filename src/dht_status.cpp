#include "dht_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension_util.hpp"

#include <sstream>
#include <cstring>

namespace duckdb {

static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

static bool starts_with(const std::string& str, const char* prefix) {
    return str.compare(0, strlen(prefix), prefix) == 0;
}


static bool try_stoi(const std::string& str, int& result) {
    try {
        result = std::stoi(str);
        return true;
    } catch (...) {
        result = 0;
        return false;
    }
}

static bool try_stod(const std::string& str, double& result) {
    try {
        result = std::stod(str);
        return true;
    } catch (...) {
        result = 0.0;
        return false;
    }
}

void ParseDhtStatus(const std::string& status_str, DhtStatusInfo& info) {
    // Initialize all numeric fields to 0
    info.port = 0;
    info.ipv4_nodes = 0;
    info.ipv4_good_nodes = 0;
    info.ipv6_nodes = 0;
    info.ipv6_good_nodes = 0;
    info.storage_entries = 0;
    info.storage_addresses = 0;
    info.ipv4_searches = 0;
    info.ipv4_searches_done = 0;
    info.ipv6_searches = 0;
    info.ipv6_searches_done = 0;
    info.announcements = 0;
    info.blocklist = 0;
    info.traffic_in = 0.0;
    info.traffic_out = 0.0;

    std::istringstream stream(status_str);
    std::string line;

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) continue;

        if (starts_with(line, "DHTd")) {
            size_t paren = line.find('(');
            if (paren != std::string::npos) {
                info.version = trim(line.substr(5, paren - 5));
            }
        }
        else if (starts_with(line, "DHT id:")) {
            info.node_id = trim(line.substr(8));
        }
        else if (starts_with(line, "DHT uptime:")) {
            info.uptime = trim(line.substr(11));
        }
        else if (starts_with(line, "DHT listen on:")) {
            size_t port_pos = line.find("port:");
            if (port_pos != std::string::npos) {
                std::string port_str = trim(line.substr(port_pos + 5));
                try_stoi(port_str, info.port);
            }
            info.listen_info = trim(line.substr(13, line.find("port:") - 13));
        }
        else if (starts_with(line, "DHT nodes:")) {
            int n1, n2, n3, n4;
            if (sscanf(line.c_str(), "DHT nodes: %d IPv4 (%d good), %d IPv6 (%d good)",
                      &n1, &n2, &n3, &n4) == 4) {
                info.ipv4_nodes = n1;
                info.ipv4_good_nodes = n2;
                info.ipv6_nodes = n3;
                info.ipv6_good_nodes = n4;
            }
        }
        else if (starts_with(line, "DHT storage:")) {
            int n1, n2;
            if (sscanf(line.c_str(), "DHT storage: %d entries with %d addresses",
                      &n1, &n2) == 2) {
                info.storage_entries = n1;
                info.storage_addresses = n2;
            }
        }
        else if (starts_with(line, "DHT searches:")) {
            int n1, n2, n3, n4;
            if (sscanf(line.c_str(), "DHT searches: %d IPv4 (%d done), %d IPv6 active (%d done)",
                      &n1, &n2, &n3, &n4) == 4) {
                info.ipv4_searches = n1;
                info.ipv4_searches_done = n2;
                info.ipv6_searches = n3;
                info.ipv6_searches_done = n4;
            }
        }
        else if (starts_with(line, "DHT announcements:")) {
            try_stoi(trim(line.substr(17)), info.announcements);
        }
        else if (starts_with(line, "DHT blocklist:")) {
            try_stoi(trim(line.substr(14)), info.blocklist);
        }
        else if (starts_with(line, "DHT traffic:")) {
            std::string traffic = line.substr(12);
            size_t in_pos = traffic.find("(in)");
            size_t out_pos = traffic.find("(out)");
            size_t slash_pos = traffic.find("/");

            if (in_pos != std::string::npos && out_pos != std::string::npos && slash_pos != std::string::npos) {
                std::string in_part = traffic.substr(0, slash_pos);
                std::string out_part = traffic.substr(slash_pos + 1);

                size_t comma_pos = in_part.find(",");
                if (comma_pos != std::string::npos) {
                    try_stod(trim(in_part.substr(0, comma_pos)), info.traffic_in);
                    info.traffic_in_rate = trim(in_part.substr(comma_pos + 1, in_part.find("(in)") - comma_pos - 1));
                }

                comma_pos = out_part.find(",");
                if (comma_pos != std::string::npos) {
                    try_stod(trim(out_part.substr(0, comma_pos)), info.traffic_out);
                    info.traffic_out_rate = trim(out_part.substr(comma_pos + 1, out_part.find("(out)") - comma_pos - 1));
                }
            }
        }
    }
}

} // namespace duckdb
