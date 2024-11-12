#define DUCKDB_EXTENSION_MAIN
#include "dht_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <regex>

namespace duckdb {

static std::string GetDhtdSocketPath() {
    const char* env_socket = std::getenv("DUCKDB_DHTD_SOCKET");
    if (env_socket != nullptr && strlen(env_socket) > 0) {
        return std::string(env_socket);
    }
    return "/tmp/dhtd.sock";
}

static const char* DEFAULT_DHTD_SOCKET = GetDhtdSocketPath();

// Function to compute SHA-256 hash of input using modern OpenSSL API
static std::string ComputeSHA256(const std::string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP context");
    }

    if(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize digest");
    }

    if(EVP_DigestUpdate(ctx, input.c_str(), input.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update digest");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if(EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(ctx);
    
    std::stringstream ss;
    for(unsigned int i = 0; i < lengthOfHash; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    // Take first 40 chars to match dhtd's 20-byte (160-bit) hash requirement
    return ss.str().substr(0, 40);
}

// Validate and potentially convert input to hash
static std::string ValidateOrHashInput(const std::string& input) {
    // Check if input is already a valid 40-char hex hash
    if (input.length() == 40) {
        bool is_valid_hex = true;
        for (char c : input) {
            if (!std::isxdigit(c)) {
                is_valid_hex = false;
                break;
            }
        }
        if (is_valid_hex) {
            return input;
        }
    }
    
    // Not a valid hash, compute hash from input
    return ComputeSHA256(input);
}

// Helper function to send command to dhtd and get response
static string_t CommunicateWithDhtd(Vector& result, const std::string& command) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DEFAULT_DHTD_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        throw std::runtime_error("Failed to connect to dhtd: " + std::string(strerror(errno)));
    }

    std::string cmd = command + "\n";
    if (write(sock, cmd.c_str(), cmd.length()) < 0) {
        close(sock);
        throw std::runtime_error("Failed to send command: " + std::string(strerror(errno)));
    }

    std::string response;
    char buffer[1024];
    while (true) {
        ssize_t bytes = read(sock, buffer, sizeof(buffer));
        if (bytes <= 0) break;
        response.append(buffer, bytes);
    }

    close(sock);
    return StringVector::AddString(result, response);
}

// DHT Search function
static void DHTSearchFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &id_vector = args.data[0];
    
    UnaryExecutor::Execute<string_t, string_t>(
        id_vector, result, args.size(),
        [&](string_t id) {
            std::string hash = ValidateOrHashInput(id.GetString());
            std::string command = "search " + hash;
            return CommunicateWithDhtd(result, command);
        });
}

// DHT Query function (search + results)
static void DHTQueryFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &id_vector = args.data[0];
    
    UnaryExecutor::Execute<string_t, string_t>(
        id_vector, result, args.size(),
        [&](string_t id) {
            std::string hash = ValidateOrHashInput(id.GetString());
            std::string command = "query " + hash;
            return CommunicateWithDhtd(result, command);
        });
}

// DHT Announce function
static void DHTAnnounceFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &id_vector = args.data[0];
    auto &port_vector = args.data[1];
    
    UnaryExecutor::Execute<string_t, string_t>(
        id_vector, result, args.size(),
        [&](string_t id) {
            std::string hash = ValidateOrHashInput(id.GetString());
            auto port = ((int32_t*)port_vector.GetData())[0];
            std::string command = "announce-start " + hash + ":" + std::to_string(port);
            return CommunicateWithDhtd(result, command);
        });
}

// DHT Stop Announce function
static void DHTStopAnnounceFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &id_vector = args.data[0];
    
    UnaryExecutor::Execute<string_t, string_t>(
        id_vector, result, args.size(),
        [&](string_t id) {
            std::string hash = ValidateOrHashInput(id.GetString());
            std::string command = "announce-stop " + hash;
            return CommunicateWithDhtd(result, command);
        });
}

// DHT Status function
static void DHTStatusFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &dummy_vector = args.data[0];
    
    UnaryExecutor::Execute<string_t, string_t>(
        dummy_vector, result, args.size(),
        [&](string_t dummy) {
            return CommunicateWithDhtd(result, "status");
        });
}

// DHT Add Peer function
static void DHTPeerFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &address_vector = args.data[0];
    
    UnaryExecutor::Execute<string_t, string_t>(
        address_vector, result, args.size(),
        [&](string_t address) {
            std::string command = "peer " + address.GetString();
            return CommunicateWithDhtd(result, command);
        });
}

// Compute hash function (exposed for testing/verification)
static void DHTHashFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &input_vector = args.data[0];
    
    UnaryExecutor::Execute<string_t, string_t>(
        input_vector, result, args.size(),
        [&](string_t input) {
            std::string hash = ComputeSHA256(input.GetString());
            return StringVector::AddString(result, hash);
        });
}

// Table function structures and implementation
struct DhtResultsBindData : public TableFunctionData {
    std::string hash;
};

struct DhtResultsGlobalState : public GlobalTableFunctionState {
    DhtResultsGlobalState() : position(0) {}
    
    std::vector<std::pair<std::string, uint16_t>> results;
    idx_t position;

    static unique_ptr<GlobalTableFunctionState> Init(ClientContext &context, TableFunctionInitInput &input) {
        return make_uniq<DhtResultsGlobalState>();
    }
};

static unique_ptr<FunctionData> DhtResultsBind(ClientContext &context, TableFunctionBindInput &input,
                                             vector<LogicalType> &return_types, vector<string> &names) {
    auto result = make_uniq<DhtResultsBindData>();
    
    // Validate we have exactly one parameter
    if (input.inputs.size() != 1 || input.inputs[0].IsNull()) {
        throw std::runtime_error("DHT results table function requires one non-null parameter");
    }

    // Get the hash parameter
    result->hash = input.inputs[0].ToString();
    result->hash = ValidateOrHashInput(result->hash);

    // Define the table structure
    return_types = {LogicalType::VARCHAR, LogicalType::INTEGER};
    names = {"address", "port"};

    return std::move(result);
}

static void DhtResultsFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
    auto &bind_data = data_p.bind_data->Cast<DhtResultsBindData>();
    auto &state = data_p.global_state->Cast<DhtResultsGlobalState>();
    
    // If this is the first call, fetch results
    if (state.position == 0) {
        // Get results from dhtd
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            throw std::runtime_error("Failed to create socket: " + std::string(strerror(errno)));
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, DEFAULT_DHTD_SOCKET, sizeof(addr.sun_path) - 1);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            throw std::runtime_error("Failed to connect to dhtd: " + std::string(strerror(errno)));
        }

        // Send results command
        std::string cmd = "results " + bind_data.hash + "\n";
        if (write(sock, cmd.c_str(), cmd.length()) < 0) {
            close(sock);
            throw std::runtime_error("Failed to send command: " + std::string(strerror(errno)));
        }

        // Read and parse response
        std::string response;
        char buffer[1024];
        while (true) {
            ssize_t bytes = read(sock, buffer, sizeof(buffer));
            if (bytes <= 0) break;
            response.append(buffer, bytes);
        }
        close(sock);

        // Parse results - format is [addr]:port or addr:port for each line
        std::istringstream stream(response);
        std::string line;
        std::regex pattern(R"((\[([^\]]+)\]|([^\]:]+ ))[:]([\d]+))");

        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            
            std::smatch matches;
            if (std::regex_match(line, matches, pattern)) {
                std::string addr = matches[2].matched ? matches[2].str() : matches[3].str();
                uint16_t port = std::stoi(matches[4].str());
                state.results.push_back({addr, port});
            }
        }
    }

    // Output up to STANDARD_VECTOR_SIZE results
    idx_t count = 0;
    auto addr_data = FlatVector::GetData<string_t>(output.data[0]);
    auto port_data = FlatVector::GetData<int32_t>(output.data[1]);

    while (state.position < state.results.size() && count < STANDARD_VECTOR_SIZE) {
        const auto& result = state.results[state.position];
        addr_data[count] = StringVector::AddString(output.data[0], result.first);
        port_data[count] = result.second;
        count++;
        state.position++;
    }

    output.SetCardinality(count);
}

static void LoadInternal(DatabaseInstance &instance) {
    // Register scalar functions
    ExtensionUtil::RegisterFunction(instance, 
        ScalarFunction("dht_search", {LogicalType::VARCHAR}, LogicalType::VARCHAR, DHTSearchFunction));
    
    ExtensionUtil::RegisterFunction(instance,
        ScalarFunction("dht_query", {LogicalType::VARCHAR}, LogicalType::VARCHAR, DHTQueryFunction));
    
    ExtensionUtil::RegisterFunction(instance,
        ScalarFunction("dht_announce", {LogicalType::VARCHAR, LogicalType::INTEGER}, 
                      LogicalType::VARCHAR, DHTAnnounceFunction));
    
    ExtensionUtil::RegisterFunction(instance,
        ScalarFunction("dht_stop_announce", {LogicalType::VARCHAR}, 
                      LogicalType::VARCHAR, DHTStopAnnounceFunction));
    
    ExtensionUtil::RegisterFunction(instance,
        ScalarFunction("dht_status", {LogicalType::VARCHAR}, 
                      LogicalType::VARCHAR, DHTStatusFunction));
    
    ExtensionUtil::RegisterFunction(instance,
        ScalarFunction("dht_peer", {LogicalType::VARCHAR}, 
                      LogicalType::VARCHAR, DHTPeerFunction));
    
    ExtensionUtil::RegisterFunction(instance,
        ScalarFunction("dht_hash", {LogicalType::VARCHAR}, 
                      LogicalType::VARCHAR, DHTHashFunction));

    // Register table function
    TableFunction dht_results("dht_results", {LogicalType::VARCHAR}, DhtResultsFunction, DhtResultsBind, 
                            DhtResultsGlobalState::Init);
    ExtensionUtil::RegisterFunction(instance, dht_results);
}

void DhtExtension::Load(DuckDB &db) {
    LoadInternal(*db.instance);
}

std::string DhtExtension::Name() {
    return "dht";
}

std::string DhtExtension::Version() const {
#ifdef EXT_VERSION_DHT
    return EXT_VERSION_DHT;
#else
    return "";
#endif
}

} // namespace duckdb

extern "C" {
DUCKDB_EXTENSION_API void dht_init(duckdb::DatabaseInstance &db) {
    duckdb::DuckDB db_wrapper(db);
    db_wrapper.LoadExtension<duckdb::DhtExtension>();
}

DUCKDB_EXTENSION_API const char *dht_version() {
    return duckdb::DuckDB::LibraryVersion();
}
}
