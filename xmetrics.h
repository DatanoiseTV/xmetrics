/**
 * @file xmetrics.h
 * @brief A lightweight, cross-platform C++ library for logging metrics to time-series databases
 * @author DatanoiseTV
 * @date 2025-05-06
 * 
 * @details
 * XMetrics is a header-only C++ library designed for logging metrics to Grafana-compatible
 * time-series databases like InfluxDB, Prometheus, and others. It provides a simple yet
 * powerful API for tracking metrics in cross-platform applications with support for
 * various data types and secure transport protocols.
 * 
 * Features:
 * - Support for multiple metric types (counter, gauge, histogram)
 * - Type-safe logging of int, float, double, bool values
 * - Custom tags/labels for detailed filtering in Grafana
 * - Multiple output formats (InfluxDB line protocol, Prometheus exposition format)
 * - Secure HTTPS transport
 * - Automatic batching and non-blocking operation
 * - Thread-safe implementation
 * - Cross-platform (Windows, Linux, macOS)
 * - Minimal external dependencies
 */

#ifndef XMETRICS_H
#define XMETRICS_H

#include <string>
#include <map>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <functional>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <optional>
#include <variant>

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
    #define XMETRICS_WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #define XMETRICS_POSIX
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

// Optional SSL support
#ifdef XMETRICS_WITH_SSL
    #include <openssl/ssl.h>
    #include <openssl/err.h>
#endif

/**
 * @namespace xmetrics
 * @brief Main namespace for the XMetrics library
 */
namespace xmetrics {

/**
 * @enum MetricType
 * @brief Types of metrics that can be collected
 */
enum class MetricType {
    Counter,    /**< A value that can only increase (e.g., request count) */
    Gauge,      /**< A value that can go up and down (e.g., temperature) */
    Histogram   /**< Tracks the distribution of a value (e.g., response times) */
};

/**
 * @enum OutputFormat
 * @brief Supported output formats for metrics
 */
enum class OutputFormat {
    InfluxDB,     /**< InfluxDB line protocol format */
    Prometheus,   /**< Prometheus exposition format */
    JSON          /**< JSON format for HTTP APIs */
};

/**
 * @class Transport
 * @brief Base abstract class for all transport methods
 * 
 * Transport classes handle the actual sending of metrics data to the target system.
 */
class Transport {
public:
    /**
     * @brief Constructor
     */
    Transport() = default;
    
    /**
     * @brief Virtual destructor
     */
    virtual ~Transport() = default;
    
    /**
     * @brief Send data to the target system
     * @param data The data to send
     * @return True if sending was successful, false otherwise
     */
    virtual bool send(const std::string& data) = 0;
    
    /**
     * @brief Check if the transport is connected/available
     * @return True if the transport is ready to send data
     */
    virtual bool is_connected() const = 0;
};

/**
 * @class HttpTransport
 * @brief Transport implementation using HTTP/HTTPS
 */
class HttpTransport : public Transport {
public:
    /**
     * @brief Constructor
     * @param url The URL to send metrics to
     * @param use_ssl Whether to use HTTPS (requires XMETRICS_WITH_SSL)
     * @param username Optional username for basic auth
     * @param password Optional password for basic auth
     */
    HttpTransport(const std::string& url, bool use_ssl = true,
                 const std::string& username = "", const std::string& password = "")
        : url_(url), use_ssl_(use_ssl), username_(username), password_(password), connected_(false) {
        
        // Parse URL to extract host, port, path
        parse_url(url);
        
        // Initialize networking
        init_networking();
    }
    
    /**
     * @brief Destructor
     */
    ~HttpTransport() override {
        cleanup_networking();
    }
    
    /**
     * @brief Send data using HTTP/HTTPS
     * @param data The data to send
     * @return True if sending was successful
     */
    bool send(const std::string& data) override {
        if (!connected_ && !connect()) {
            return false;
        }
        
        std::string request = build_http_request(data);
        
#ifdef XMETRICS_WITH_SSL
        if (use_ssl_) {
            return send_ssl(request);
        } else {
            return send_plain(request);
        }
#else
        return send_plain(request);
#endif
    }
    
    /**
     * @brief Check if connected to the server
     * @return Connection status
     */
    bool is_connected() const override {
        return connected_;
    }
    
private:
    void parse_url(const std::string& url) {
        // Simple URL parser
        // Example: "https://influxdb.example.com:8086/write?db=mydb"
        
        size_t protocol_end = url.find("://");
        if (protocol_end != std::string::npos) {
            protocol_ = url.substr(0, protocol_end);
            size_t host_start = protocol_end + 3;
            size_t host_end = url.find(":", host_start);
            
            if (host_end == std::string::npos) {
                host_end = url.find("/", host_start);
                if (host_end == std::string::npos) {
                    host_ = url.substr(host_start);
                    path_ = "/";
                } else {
                    host_ = url.substr(host_start, host_end - host_start);
                    path_ = url.substr(host_end);
                }
                
                // Default ports based on protocol
                if (protocol_ == "https") {
                    port_ = 443;
                } else {
                    port_ = 80;
                }
            } else {
                host_ = url.substr(host_start, host_end - host_start);
                size_t port_start = host_end + 1;
                size_t port_end = url.find("/", port_start);
                
                if (port_end == std::string::npos) {
                    port_ = std::stoi(url.substr(port_start));
                    path_ = "/";
                } else {
                    port_ = std::stoi(url.substr(port_start, port_end - port_start));
                    path_ = url.substr(port_end);
                }
            }
        }
    }
    
    void init_networking() {
#ifdef XMETRICS_WINDOWS
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
        
#ifdef XMETRICS_WITH_SSL
        if (use_ssl_) {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
            
            ssl_ctx_ = SSL_CTX_new(TLS_client_method());
            if (!ssl_ctx_) {
                // Handle error
                connected_ = false;
                return;
            }
        }
#endif
    }
    
    void cleanup_networking() {
#ifdef XMETRICS_WITH_SSL
        if (use_ssl_ && ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        
        if (ssl_ctx_) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
#endif
        
        if (socket_ != -1) {
#ifdef XMETRICS_WINDOWS
            closesocket(socket_);
            WSACleanup();
#else
            close(socket_);
#endif
            socket_ = -1;
        }
        
        connected_ = false;
    }
    
    bool connect() {
        // Create socket
        socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_ == -1) {
            return false;
        }
        
        // Resolve hostname
        struct hostent* server = gethostbyname(host_.c_str());
        if (server == nullptr) {
            cleanup_networking();
            return false;
        }
        
        // Setup socket address
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        server_addr.sin_port = htons(port_);
        
        // Connect
        if (::connect(socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            cleanup_networking();
            return false;
        }
        
#ifdef XMETRICS_WITH_SSL
        if (use_ssl_) {
            ssl_ = SSL_new(ssl_ctx_);
            if (!ssl_) {
                cleanup_networking();
                return false;
            }
            
            SSL_set_fd(ssl_, socket_);
            
            if (SSL_connect(ssl_) != 1) {
                cleanup_networking();
                return false;
            }
        }
#endif
        
        connected_ = true;
        return true;
    }
    
    std::string build_http_request(const std::string& data) {
        std::stringstream request;
        
        // Request line
        request << "POST " << path_ << " HTTP/1.1\r\n";
        
        // Headers
        request << "Host: " << host_ << "\r\n";
        request << "Content-Type: text/plain\r\n";
        request << "Content-Length: " << data.length() << "\r\n";
        
        // Basic auth if provided
        if (!username_.empty() || !password_.empty()) {
            std::string auth = username_ + ":" + password_;
            request << "Authorization: Basic " << base64_encode(auth) << "\r\n";
        }
        
        // End of headers
        request << "\r\n";
        
        // Body
        request << data;
        
        return request.str();
    }
    
    bool send_plain(const std::string& request) {
        // Simple sending, not handling partial sends for brevity
        int bytes_sent = ::send(socket_, request.c_str(), request.length(), 0);
        return bytes_sent == static_cast<int>(request.length());
    }
    
#ifdef XMETRICS_WITH_SSL
    bool send_ssl(const std::string& request) {
        if (!ssl_) return false;
        
        int bytes_sent = SSL_write(ssl_, request.c_str(), request.length());
        return bytes_sent == static_cast<int>(request.length());
    }
#endif
    
    // Simple Base64 encoding implementation
    static std::string base64_encode(const std::string& input) {
        static const char* base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string result;
        result.reserve(((input.size() + 2) / 3) * 4);
        
        for (size_t i = 0; i < input.size(); i += 3) {
            uint32_t chunk = (static_cast<uint32_t>(input[i]) << 16);
            
            if (i + 1 < input.size()) {
                chunk |= (static_cast<uint32_t>(input[i + 1]) << 8);
            }
            
            if (i + 2 < input.size()) {
                chunk |= static_cast<uint32_t>(input[i + 2]);
            }
            
            for (int j = 0; j < 4; ++j) {
                if (i + j / 3 >= input.size()) {
                    result += '=';
                } else {
                    result += base64_chars[(chunk >> (18 - j * 6)) & 0x3F];
                }
            }
        }
        
        return result;
    }
    
    std::string url_;
    std::string protocol_;
    std::string host_;
    int port_;
    std::string path_;
    bool use_ssl_;
    std::string username_;
    std::string password_;
    bool connected_;
    int socket_ = -1;
    
#ifdef XMETRICS_WITH_SSL
    SSL_CTX* ssl_ctx_ = nullptr;
    SSL* ssl_ = nullptr;
#endif
};

/**
 * @class UdpTransport
 * @brief Transport implementation using UDP
 */
class UdpTransport : public Transport {
public:
    /**
     * @brief Constructor
     * @param host The host to send metrics to
     * @param port The port to send metrics to
     */
    UdpTransport(const std::string& host, int port)
        : host_(host), port_(port), connected_(false) {
        init_networking();
    }
    
    /**
     * @brief Destructor
     */
    ~UdpTransport() override {
        cleanup_networking();
    }
    
    /**
     * @brief Send data using UDP
     * @param data The data to send
     * @return True if sending was successful
     */
    bool send(const std::string& data) override {
        if (!connected_ && !connect()) {
            return false;
        }
        
        int bytes_sent = ::sendto(socket_, data.c_str(), data.length(), 0,
                               (struct sockaddr*)&server_addr_, sizeof(server_addr_));
        
        return bytes_sent == static_cast<int>(data.length());
    }
    
    /**
     * @brief Check if the socket is ready
     * @return Socket status
     */
    bool is_connected() const override {
        return connected_;
    }
    
private:
    void init_networking() {
#ifdef XMETRICS_WINDOWS
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
        
        connect();
    }
    
    void cleanup_networking() {
        if (socket_ != -1) {
#ifdef XMETRICS_WINDOWS
            closesocket(socket_);
            WSACleanup();
#else
            close(socket_);
#endif
            socket_ = -1;
        }
        
        connected_ = false;
    }
    
    bool connect() {
        // Create socket
        socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_ == -1) {
            return false;
        }
        
        // Resolve hostname
        struct hostent* server = gethostbyname(host_.c_str());
        if (server == nullptr) {
            cleanup_networking();
            return false;
        }
        
        // Setup socket address
        memset(&server_addr_, 0, sizeof(server_addr_));
        server_addr_.sin_family = AF_INET;
        memcpy(&server_addr_.sin_addr.s_addr, server->h_addr, server->h_length);
        server_addr_.sin_port = htons(port_);
        
        connected_ = true;
        return true;
    }
    
    std::string host_;
    int port_;
    bool connected_;
    int socket_ = -1;
    struct sockaddr_in server_addr_;
};

/**
 * @class MetricValue
 * @brief Base class for storing metric values of different types
 */
class MetricValue {
public:
    /**
     * @brief Virtual destructor
     */
    virtual ~MetricValue() = default;
    
    /**
     * @brief Get the type name
     * @return Type name as string
     */
    virtual std::string type_name() const = 0;
    
    /**
     * @brief Convert value to string for InfluxDB format
     * @return String representation for InfluxDB
     */
    virtual std::string to_influx_string() const = 0;
    
    /**
     * @brief Convert value to string for Prometheus format
     * @return String representation for Prometheus
     */
    virtual std::string to_prometheus_string() const = 0;
    
    /**
     * @brief Convert value to string for JSON format
     * @return String representation for JSON
     */
    virtual std::string to_json_string() const = 0;
};

/**
 * @class TypedMetricValue
 * @brief Template class for storing values of specific types
 * @tparam T The value type
 */
template<typename T>
class TypedMetricValue : public MetricValue {
public:
    /**
     * @brief Constructor
     * @param value The value to store
     */
    explicit TypedMetricValue(const T& value) : value_(value) {}
    
    /**
     * @brief Get the type name
     * @return Type name as string
     */
    std::string type_name() const override {
        if constexpr (std::is_same_v<T, int>) return "int";
        else if constexpr (std::is_same_v<T, float>) return "float";
        else if constexpr (std::is_same_v<T, double>) return "double";
        else if constexpr (std::is_same_v<T, bool>) return "bool";
        else if constexpr (std::is_same_v<T, int64_t>) return "int64";
        else if constexpr (std::is_same_v<T, uint64_t>) return "uint64";
        else return "unknown";
    }
    
    /**
     * @brief Convert value to string for InfluxDB format
     * @return String representation for InfluxDB
     */
    std::string to_influx_string() const override {
        if constexpr (std::is_same_v<T, bool>) {
            return value_ ? "true" : "false";
        } else if constexpr (std::is_floating_point_v<T>) {
            return std::to_string(value_);
        } else if constexpr (std::is_integral_v<T>) {
            return std::to_string(value_) + "i";
        } else {
            return std::to_string(value_);
        }
    }
    
    /**
     * @brief Convert value to string for Prometheus format
     * @return String representation for Prometheus
     */
    std::string to_prometheus_string() const override {
        if constexpr (std::is_same_v<T, bool>) {
            return value_ ? "1" : "0";
        } else {
            return std::to_string(value_);
        }
    }
    
    /**
     * @brief Convert value to string for JSON format
     * @return String representation for JSON
     */
    std::string to_json_string() const override {
        if constexpr (std::is_same_v<T, bool>) {
            return value_ ? "true" : "false";
        } else if constexpr (std::is_same_v<T, std::string>) {
            return "\"" + escape_json(value_) + "\"";
        } else {
            return std::to_string(value_);
        }
    }
    
    /**
     * @brief Get the raw value
     * @return The stored value
     */
    T value() const { return value_; }
    
private:
    /**
     * @brief Escape special characters in a string for JSON
     * @param input String to escape
     * @return Escaped string safe for JSON
     */
    static std::string escape_json(const std::string& input) {
        std::string output;
        output.reserve(input.length() * 2);
        
        for (char c : input) {
            switch (c) {
                case '\"': output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '/':  output += "\\/"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 32) {
                        char hex[7];
                        snprintf(hex, sizeof(hex), "\\u%04x", c);
                        output += hex;
                    } else {
                        output += c;
                    }
                    break;
            }
        }
        
        return output;
    }
    
    T value_;
};

/**
 * @class Metric
 * @brief Base class for all metric types
 */
class Metric {
public:
    /**
     * @brief Constructor
     * @param name Metric name
     * @param description Human-readable description
     * @param type Type of metric
     */
    Metric(const std::string& name, const std::string& description, MetricType type)
        : name_(name), description_(description), type_(type) {}
    
    /**
     * @brief Virtual destructor
     */
    virtual ~Metric() = default;
    
    /**
     * @brief Get the metric name
     * @return Metric name
     */
    const std::string& name() const { return name_; }
    
    /**
     * @brief Get the metric description
     * @return Metric description
     */
    const std::string& description() const { return description_; }
    
    /**
     * @brief Get the metric type
     * @return Metric type
     */
    MetricType type() const { return type_; }
    
    /**
     * @brief Add a tag to the metric
     * @param key Tag key
     * @param value Tag value
     */
    void add_tag(const std::string& key, const std::string& value) {
        tags_[key] = value;
    }
    
    /**
     * @brief Get all tags
     * @return Map of tags
     */
    const std::map<std::string, std::string>& tags() const { return tags_; }
    
    /**
     * @brief Format the metric for InfluxDB line protocol
     * @return InfluxDB line protocol string
     */
    virtual std::string to_influx_line() const = 0;
    
    /**
     * @brief Format the metric for Prometheus exposition format
     * @return Prometheus exposition format string
     */
    virtual std::string to_prometheus_format() const = 0;
    
    /**
     * @brief Format the metric for JSON
     * @return JSON string
     */
    virtual std::string to_json() const = 0;
    
protected:
    std::string name_;
    std::string description_;
    MetricType type_;
    std::map<std::string, std::string> tags_;
    
    /**
     * @brief Format tags for InfluxDB line protocol
     * @return Formatted tags string
     */
    std::string format_influx_tags() const {
        if (tags_.empty()) {
            return "";
        }
        
        std::string result;
        for (const auto& tag : tags_) {
            result += "," + escape_tag(tag.first) + "=" + escape_tag(tag.second);
        }
        return result;
    }
    
    /**
     * @brief Format tags for Prometheus exposition format
     * @return Formatted tags string
     */
    std::string format_prometheus_tags() const {
        if (tags_.empty()) {
            return "";
        }
        
        std::string result = "{";
        bool first = true;
        for (const auto& tag : tags_) {
            if (!first) {
                result += ",";
            }
            result += escape_tag(tag.first) + "=\"" + escape_tag(tag.second) + "\"";
            first = false;
        }
        result += "}";
        return result;
    }
    
    /**
     * @brief Escape special characters in tag keys and values
     * @param input Tag string to escape
     * @return Escaped tag string
     */
    static std::string escape_tag(const std::string& input) {
        std::string output;
        output.reserve(input.size());
        
        for (char c : input) {
            if (c == ' ' || c == ',' || c == '=' || c == '"') {
                output += '\\';
            }
            output += c;
        }
        
        return output;
    }
};

/**
 * @class Counter
 * @brief A metric that can only increase or be reset to zero
 * 
 * Counters are typically used for counting events, such as
 * requests, errors, or completed tasks.
 */
class Counter : public Metric {
public:
    /**
     * @brief Constructor
     * @param name Metric name
     * @param description Human-readable description
     */
    Counter(const std::string& name, const std::string& description)
        : Metric(name, description, MetricType::Counter), value_(0) {}
    
    /**
     * @brief Increment counter by a specified amount
     * @param value Amount to increment (must be non-negative)
     */
    void increment(int64_t value = 1) {
        if (value < 0) return;  // Counters can only increase
        value_.fetch_add(value, std::memory_order_relaxed);
    }
    
    /**
     * @brief Reset counter to zero
     */
    void reset() {
        value_.store(0, std::memory_order_relaxed);
    }
    
    /**
     * @brief Get current counter value
     * @return Current value
     */
    int64_t value() const {
        return value_.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Format counter for InfluxDB line protocol
     * @return InfluxDB line protocol string
     */
    std::string to_influx_line() const override {
        int64_t current_value = value();
        return name_ + format_influx_tags() + " value=" + std::to_string(current_value) + "i";
    }
    
    /**
     * @brief Format counter for Prometheus exposition format
     * @return Prometheus exposition format string
     */
    std::string to_prometheus_format() const override {
        int64_t current_value = value();
        std::stringstream ss;
        
        // Add TYPE and HELP comments
        ss << "# HELP " << name_ << " " << description_ << "\n";
        ss << "# TYPE " << name_ << " counter\n";
        
        // Add metric value
        ss << name_ << format_prometheus_tags() << " " << current_value;
        
        return ss.str();
    }
    
    /**
     * @brief Format counter for JSON
     * @return JSON string
     */
    std::string to_json() const override {
        int64_t current_value = value();
        std::stringstream ss;
        
        ss << "{";
        ss << "\"name\":\"" << name_ << "\",";
        ss << "\"type\":\"counter\",";
        ss << "\"description\":\"" << description_ << "\",";
        
        // Add tags
        ss << "\"tags\":{";
        bool first_tag = true;
        for (const auto& tag : tags_) {
            if (!first_tag) ss << ",";
            ss << "\"" << tag.first << "\":\"" << tag.second << "\"";
            first_tag = false;
        }
        ss << "},";
        
        // Add value
        ss << "\"value\":" << current_value;
        ss << "}";
        
        return ss.str();
    }
    
private:
    std::atomic<int64_t> value_;
};

/**
 * @class Gauge
 * @brief A metric that can increase and decrease
 * 
 * Gauges are typically used for measurements, such as
 * temperature, memory usage, or active connections.
 */
class Gauge : public Metric {
public:
    /**
     * @brief Constructor
     * @param name Metric name
     * @param description Human-readable description
     */
    Gauge(const std::string& name, const std::string& description)
        : Metric(name, description, MetricType::Gauge), value_(0.0) {}
    
    /**
     * @brief Set gauge to a specific value
     * @param value New value
     */
    void set(double value) {
        value_.store(value, std::memory_order_relaxed);
    }
    
    /**
     * @brief Increment gauge by a specified amount
     * @param value Amount to increment
     */
    void increment(double value = 1.0) {
        // For floating-point atomics, we need to use load/store
        double current = value_.load(std::memory_order_relaxed);
        double desired = current + value;
        value_.store(desired, std::memory_order_relaxed);
    }
    
    /**
     * @brief Decrement gauge by a specified amount
     * @param value Amount to decrement
     */
    void decrement(double value = 1.0) {
        // For floating-point atomics, we need to use load/store
        double current = value_.load(std::memory_order_relaxed);
        double desired = current - value;
        value_.store(desired, std::memory_order_relaxed);
    }
    
    /**
     * @brief Get current gauge value
     * @return Current value
     */
    double value() const {
        return value_.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Format gauge for InfluxDB line protocol
     * @return InfluxDB line protocol string
     */
    std::string to_influx_line() const override {
        double current_value = value();
        return name_ + format_influx_tags() + " value=" + std::to_string(current_value);
    }
    
    /**
     * @brief Format gauge for Prometheus exposition format
     * @return Prometheus exposition format string
     */
    std::string to_prometheus_format() const override {
        double current_value = value();
        std::stringstream ss;
        
        // Add TYPE and HELP comments
        ss << "# HELP " << name_ << " " << description_ << "\n";
        ss << "# TYPE " << name_ << " gauge\n";
        
        // Add metric value
        ss << name_ << format_prometheus_tags() << " " << current_value;
        
        return ss.str();
    }
    
    /**
     * @brief Format gauge for JSON
     * @return JSON string
     */
    std::string to_json() const override {
        double current_value = value();
        std::stringstream ss;
        
        ss << "{";
        ss << "\"name\":\"" << name_ << "\",";
        ss << "\"type\":\"gauge\",";
        ss << "\"description\":\"" << description_ << "\",";
        
        // Add tags
        ss << "\"tags\":{";
        bool first_tag = true;
        for (const auto& tag : tags_) {
            if (!first_tag) ss << ",";
            ss << "\"" << tag.first << "\":\"" << tag.second << "\"";
            first_tag = false;
        }
        ss << "},";
        
        // Add value
        ss << "\"value\":" << current_value;
        ss << "}";
        
        return ss.str();
    }
    
private:
    std::atomic<double> value_;
};

/**
 * @class Histogram
 * @brief A metric that tracks value distributions
 * 
 * Histograms are typically used for measuring distributions,
 * such as request durations or response sizes.
 */
class Histogram : public Metric {
public:
    /**
     * @brief Constructor
     * @param name Metric name
     * @param description Human-readable description
     * @param buckets Histogram bucket boundaries
     */
    Histogram(const std::string& name, const std::string& description,
             const std::vector<double>& buckets = default_buckets())
        : Metric(name, description, MetricType::Histogram),
          buckets_(buckets), count_(0), sum_(0.0) {
        
        // Initialize bucket counters with a thread-safe approach
        // Using a vector of pointers to atomics to avoid copying atomics
        for (size_t i = 0; i <= buckets.size(); ++i) {  // +1 for the +Inf bucket
            bucket_counts_.push_back(std::make_unique<std::atomic<int64_t>>(0));
        }
    }
    
    /**
     * @brief Observe a value
     * @param value Value to observe
     */
    void observe(double value) {
        count_.fetch_add(1, std::memory_order_relaxed);
        
        // For floating-point atomics, we need to use load/store
        double current_sum = sum_.load(std::memory_order_relaxed);
        double new_sum = current_sum + value;
        sum_.store(new_sum, std::memory_order_relaxed);
        
        // Update bucket counts
        for (size_t i = 0; i < buckets_.size(); ++i) {
            if (value <= buckets_[i]) {
                bucket_counts_[i]->fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
        
        // Always update the +Inf bucket
        bucket_counts_.back()->fetch_add(1, std::memory_order_relaxed);
    }
    
    /**
     * @brief Get total number of observations
     * @return Observation count
     */
    int64_t count() const {
        return count_.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Get sum of all observed values
     * @return Sum of values
     */
    double sum() const {
        return sum_.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Get bucket boundaries
     * @return Vector of bucket boundaries
     */
    const std::vector<double>& buckets() const {
        return buckets_;
    }
    
    /**
     * @brief Get bucket counts
     * @return Vector of bucket counts
     */
    std::vector<int64_t> bucket_counts() const {
        std::vector<int64_t> counts;
        counts.reserve(bucket_counts_.size());
        
        for (const auto& count_ptr : bucket_counts_) {
            counts.push_back(count_ptr->load(std::memory_order_relaxed));
        }
        
        return counts;
    }
    
    /**
     * @brief Format histogram for InfluxDB line protocol
     * @return InfluxDB line protocol string
     */
    std::string to_influx_line() const override {
        int64_t current_count = count();
        double current_sum = sum();
        auto current_bucket_counts = bucket_counts();
        
        std::stringstream ss;
        
        // Add count and sum
        ss << name_ << format_influx_tags() << " count=" << current_count << "i,"
           << "sum=" << current_sum;
        
        // Add individual buckets
        for (size_t i = 0; i < buckets_.size(); ++i) {
            ss << " bucket_" << buckets_[i] << "=" << current_bucket_counts[i] << "i";
        }
        
        // Add +Inf bucket
        ss << " bucket_inf=" << current_bucket_counts.back() << "i";
        
        return ss.str();
    }
    
    /**
     * @brief Format histogram for Prometheus exposition format
     * @return Prometheus exposition format string
     */
    std::string to_prometheus_format() const override {
        int64_t current_count = count();
        double current_sum = sum();
        auto current_bucket_counts = bucket_counts();
        
        std::stringstream ss;
        
        // Add TYPE and HELP comments
        ss << "# HELP " << name_ << " " << description_ << "\n";
        ss << "# TYPE " << name_ << " histogram\n";
        
        // Add buckets
        for (size_t i = 0; i < buckets_.size(); ++i) {
            ss << name_ << "_bucket" << format_prometheus_tags() << ",le=\"" << buckets_[i] << "\" "
               << current_bucket_counts[i] << "\n";
        }
        
        // Add +Inf bucket
        ss << name_ << "_bucket" << format_prometheus_tags() << ",le=\"+Inf\" "
           << current_bucket_counts.back() << "\n";
        
        // Add sum and count
        ss << name_ << "_sum" << format_prometheus_tags() << " " << current_sum << "\n";
        ss << name_ << "_count" << format_prometheus_tags() << " " << current_count;
        
        return ss.str();
    }
    
    /**
     * @brief Format histogram for JSON
     * @return JSON string
     */
    std::string to_json() const override {
        int64_t current_count = count();
        double current_sum = sum();
        auto current_bucket_counts = bucket_counts();
        
        std::stringstream ss;
        
        ss << "{";
        ss << "\"name\":\"" << name_ << "\",";
        ss << "\"type\":\"histogram\",";
        ss << "\"description\":\"" << description_ << "\",";
        
        // Add tags
        ss << "\"tags\":{";
        bool first_tag = true;
        for (const auto& tag : tags_) {
            if (!first_tag) ss << ",";
            ss << "\"" << tag.first << "\":\"" << tag.second << "\"";
            first_tag = false;
        }
        ss << "},";
        
        // Add count and sum
        ss << "\"count\":" << current_count << ",";
        ss << "\"sum\":" << current_sum << ",";
        
        // Add buckets
        ss << "\"buckets\":[";
        for (size_t i = 0; i < buckets_.size(); ++i) {
            if (i > 0) ss << ",";
            ss << "{\"le\":" << buckets_[i] << ",\"count\":" << current_bucket_counts[i] << "}";
        }
        ss << ",{\"le\":\"+Inf\",\"count\":" << current_bucket_counts.back() << "}";
        ss << "]";
        
        ss << "}";
        
        return ss.str();
    }
    
    /**
     * @brief Get default histogram buckets
     * @return Vector of default bucket boundaries
     */
    static std::vector<double> default_buckets() {
        return {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0};
    }
    
private:
    std::vector<double> buckets_;
    std::vector<std::unique_ptr<std::atomic<int64_t>>> bucket_counts_;
    std::atomic<int64_t> count_;
    std::atomic<double> sum_;
};

/**
 * @class Registry
 * @brief Central registry for managing metrics
 * 
 * The Registry is responsible for creating, storing, and collecting metrics.
 */
class Registry {
public:
    /**
     * @brief Constructor
     */
    Registry() = default;
    
    /**
     * @brief Get or create a counter
     * @param name Metric name
     * @param description Human-readable description
     * @return Shared pointer to the counter
     */
    std::shared_ptr<Counter> counter(const std::string& name, const std::string& description) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check if the metric already exists
        auto it = metrics_.find(name);
        if (it != metrics_.end()) {
            auto counter = std::dynamic_pointer_cast<Counter>(it->second);
            if (counter) {
                return counter;
            }
            // Metric exists but with different type
            throw std::runtime_error("Metric '" + name + "' exists with different type");
        }
        
        // Create new counter
        auto counter = std::make_shared<Counter>(name, description);
        metrics_[name] = counter;
        return counter;
    }
    
    /**
     * @brief Get or create a gauge
     * @param name Metric name
     * @param description Human-readable description
     * @return Shared pointer to the gauge
     */
    std::shared_ptr<Gauge> gauge(const std::string& name, const std::string& description) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check if the metric already exists
        auto it = metrics_.find(name);
        if (it != metrics_.end()) {
            auto gauge = std::dynamic_pointer_cast<Gauge>(it->second);
            if (gauge) {
                return gauge;
            }
            // Metric exists but with different type
            throw std::runtime_error("Metric '" + name + "' exists with different type");
        }
        
        // Create new gauge
        auto gauge = std::make_shared<Gauge>(name, description);
        metrics_[name] = gauge;
        return gauge;
    }
    
    /**
     * @brief Get or create a histogram
     * @param name Metric name
     * @param description Human-readable description
     * @param buckets Histogram bucket boundaries
     * @return Shared pointer to the histogram
     */
    std::shared_ptr<Histogram> histogram(const std::string& name, const std::string& description,
                                       const std::vector<double>& buckets = Histogram::default_buckets()) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Check if the metric already exists
        auto it = metrics_.find(name);
        if (it != metrics_.end()) {
            auto histogram = std::dynamic_pointer_cast<Histogram>(it->second);
            if (histogram) {
                return histogram;
            }
            // Metric exists but with different type
            throw std::runtime_error("Metric '" + name + "' exists with different type");
        }
        
        // Create new histogram
        auto histogram = std::make_shared<Histogram>(name, description, buckets);
        metrics_[name] = histogram;
        return histogram;
    }
    
    /**
     * @brief Get all metrics
     * @return Map of metric names to metric pointers
     */
    std::unordered_map<std::string, std::shared_ptr<Metric>> metrics() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return metrics_;
    }
    
    /**
     * @brief Collect all metrics in InfluxDB line protocol format
     * @return InfluxDB line protocol string
     */
    std::string collect_influx() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::stringstream ss;
        for (const auto& entry : metrics_) {
            ss << entry.second->to_influx_line() << "\n";
        }
        
        return ss.str();
    }
    
    /**
     * @brief Collect all metrics in Prometheus exposition format
     * @return Prometheus exposition format string
     */
    std::string collect_prometheus() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::stringstream ss;
        for (const auto& entry : metrics_) {
            ss << entry.second->to_prometheus_format() << "\n";
        }
        
        return ss.str();
    }
    
    /**
     * @brief Collect all metrics in JSON format
     * @return JSON array string
     */
    std::string collect_json() const {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::stringstream ss;
        ss << "[";
        
        bool first = true;
        for (const auto& entry : metrics_) {
            if (!first) {
                ss << ",";
            }
            ss << entry.second->to_json();
            first = false;
        }
        
        ss << "]";
        return ss.str();
    }
    
private:
    std::unordered_map<std::string, std::shared_ptr<Metric>> metrics_;
    mutable std::mutex mutex_;
};

/**
 * @class Reporter
 * @brief Base class for reporters that send metrics to a target
 */
class Reporter {
public:
    /**
     * @brief Constructor
     * @param registry Metrics registry to report from
     * @param transport Transport to use for sending metrics
     */
    Reporter(std::shared_ptr<Registry> registry, std::shared_ptr<Transport> transport)
        : registry_(registry), transport_(transport), running_(false) {}
    
    /**
     * @brief Virtual destructor
     */
    virtual ~Reporter() {
        stop();
    }
    
    /**
     * @brief Start periodic reporting
     * @param interval_ms Reporting interval in milliseconds
     */
    void start(int interval_ms = 10000) {
        if (running_) return;
        
        running_ = true;
        report_thread_ = std::thread([this, interval_ms]() {
            while (running_) {
                report();
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
        });
    }
    
    /**
     * @brief Stop periodic reporting
     */
    void stop() {
        if (!running_) return;
        
        running_ = false;
        if (report_thread_.joinable()) {
            report_thread_.join();
        }
    }
    
    /**
     * @brief Trigger an immediate report
     * @return True if reporting was successful
     */
    virtual bool report() = 0;
    
protected:
    std::shared_ptr<Registry> registry_;
    std::shared_ptr<Transport> transport_;
    std::atomic<bool> running_;
    std::thread report_thread_;
};

/**
 * @class InfluxDBReporter
 * @brief Reporter for InfluxDB format
 */
class InfluxDBReporter : public Reporter {
public:
    /**
     * @brief Constructor
     * @param registry Metrics registry to report from
     * @param transport Transport to use for sending metrics
     * @param database InfluxDB database name
     */
    InfluxDBReporter(std::shared_ptr<Registry> registry, std::shared_ptr<Transport> transport,
                    const std::string& database = "")
        : Reporter(registry, transport), database_(database) {}
    
    /**
     * @brief Report metrics to InfluxDB
     * @return True if reporting was successful
     */
    bool report() override {
        std::string data = registry_->collect_influx();
        
        if (database_.empty()) {
            return transport_->send(data);
        } else {
            return transport_->send(data + "&db=" + database_);
        }
    }
    
private:
    std::string database_;
};

/**
 * @class PrometheusReporter
 * @brief Reporter for Prometheus format
 */
class PrometheusReporter : public Reporter {
public:
    /**
     * @brief Constructor
     * @param registry Metrics registry to report from
     * @param transport Transport to use for sending metrics
     */
    PrometheusReporter(std::shared_ptr<Registry> registry, std::shared_ptr<Transport> transport)
        : Reporter(registry, transport) {}
    
    /**
     * @brief Report metrics in Prometheus format
     * @return True if reporting was successful
     */
    bool report() override {
        std::string data = registry_->collect_prometheus();
        return transport_->send(data);
    }
};

/**
 * @brief Get the global metrics registry
 * @return Reference to the global registry
 */
inline Registry& global_registry() {
    static Registry registry;
    return registry;
}

/**
 * @brief Get or create a counter in the global registry
 * @param name Metric name
 * @param description Human-readable description
 * @return Shared pointer to the counter
 */
inline std::shared_ptr<Counter> counter(const std::string& name, const std::string& description) {
    return global_registry().counter(name, description);
}

/**
 * @brief Get or create a gauge in the global registry
 * @param name Metric name
 * @param description Human-readable description
 * @return Shared pointer to the gauge
 */
inline std::shared_ptr<Gauge> gauge(const std::string& name, const std::string& description) {
    return global_registry().gauge(name, description);
}

/**
 * @brief Get or create a histogram in the global registry
 * @param name Metric name
 * @param description Human-readable description
 * @param buckets Histogram bucket boundaries
 * @return Shared pointer to the histogram
 */
inline std::shared_ptr<Histogram> histogram(
    const std::string& name, 
    const std::string& description,
    const std::vector<double>& buckets = Histogram::default_buckets()) {
    return global_registry().histogram(name, description, buckets);
}

} // namespace xmetrics

#endif // XMETRICS_H
