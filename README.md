# XMetrics

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/language-C%2B%2B17-green.svg)](https://en.cppreference.com/w/cpp/17)

A lightweight, header-only C++ library designed for logging metrics to time-series databases and Grafana.

## Features

- **Multiple Metric Types**: Support for counters, gauges, and histograms
- **Type Safety**: Properly handle int, float, double, bool and other numeric types
- **Easy Tagging**: Add custom tags/labels for detailed filtering in Grafana
- **Multiple Output Formats**:
  - InfluxDB line protocol
  - Prometheus exposition format
  - JSON for RESTful APIs
- **Transport Options**:
  - HTTP/HTTPS with optional SSL support
  - UDP for high-throughput, low-overhead metrics
- **Performance Optimized**:
  - Thread-safe implementation
  - Batching support
  - Non-blocking operation
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Minimal Dependencies**: Header-only with no external libraries required (except OpenSSL for HTTPS)

## Installation

Since XMetrics is a header-only library, you can simply include it in your project:

```bash
# Clone the repository
git clone https://github.com/DatanoiseTV/xmetrics.git

# Or download the header directly
wget https://raw.githubusercontent.com/DatanoiseTV/xmetrics/main/xmetrics.h
```

Then include it in your code:

```cpp
#include "xmetrics.h"
```

### SSL Support

To enable HTTPS transport, define `XMETRICS_WITH_SSL` before including the header and link against OpenSSL:

```cpp
#define XMETRICS_WITH_SSL
#include "xmetrics.h"
```

Compile with:

```bash
g++ -std=c++17 your_program.cpp -o your_program -lssl -lcrypto
```

## Basic Usage

### Creating Metrics

```cpp
#include "xmetrics.h"

int main() {
    // Get or create metrics from the global registry
    auto requests = xmetrics::counter("http_requests_total", "Total HTTP requests");
    auto temperature = xmetrics::gauge("temperature_celsius", "Current temperature in Celsius");
    auto response_time = xmetrics::histogram("http_response_time_seconds", 
                                            "HTTP response time in seconds");
    
    // Add tags/labels for filtering in Grafana
    requests->add_tag("method", "GET");
    requests->add_tag("endpoint", "/api/v1/users");
    temperature->add_tag("location", "server_room");
    response_time->add_tag("service", "auth");
    
    // Update metrics
    requests->increment();
    temperature->set(23.5);
    response_time->observe(0.42);
    
    return 0;
}
```

### Sending Metrics to InfluxDB

```cpp
#include "xmetrics.h"

int main() {
    // Create metrics as in the previous example
    
    // Create HTTP transport to InfluxDB
    auto transport = std::make_shared<xmetrics::HttpTransport>(
        "http://influxdb:8086/write?db=myapp",
        false,  // Don't use SSL
        "username",  // Optional username
        "password"   // Optional password
    );
    
    // Create reporter
    auto reporter = std::make_shared<xmetrics::InfluxDBReporter>(
        std::make_shared<xmetrics::Registry>(xmetrics::global_registry()),
        transport
    );
    
    // Start periodic reporting (every 10 seconds)
    reporter->start(10000);
    
    // Your application logic here...
    
    // Stop reporting before application exits
    reporter->stop();
    
    return 0;
}
```

### Sending Metrics with Secure HTTPS

```cpp
#define XMETRICS_WITH_SSL
#include "xmetrics.h"

int main() {
    // Create HTTP transport with SSL enabled
    auto transport = std::make_shared<xmetrics::HttpTransport>(
        "https://metrics.example.com:8086/write?db=myapp",
        true  // Use SSL
    );
    
    // Create and start reporter as in the previous example
    
    return 0;
}
```

## Advanced Usage

### Custom Registry

```cpp
// Create a custom registry
auto registry = std::make_shared<xmetrics::Registry>();

// Create metrics in the custom registry
auto requests = registry->counter("http_requests_total", "Total HTTP requests");
auto temperature = registry->gauge("temperature_celsius", "Current temperature in Celsius");

// Use the custom registry with a reporter
auto reporter = std::make_shared<xmetrics::InfluxDBReporter>(registry, transport);
```

### Prometheus Format

```cpp
// Create a Prometheus reporter
auto prometheus_reporter = std::make_shared<xmetrics::PrometheusReporter>(
    std::make_shared<xmetrics::Registry>(xmetrics::global_registry()),
    transport
);

// Get metrics in Prometheus exposition format
std::string metrics = xmetrics::global_registry().collect_prometheus();
```

### UDP Transport

```cpp
// Create UDP transport (lightweight, good for high-frequency metrics)
auto udp_transport = std::make_shared<xmetrics::UdpTransport>(
    "influxdb.example.com",
    8089  // InfluxDB UDP port
);

// Use with any reporter
auto reporter = std::make_shared<xmetrics::InfluxDBReporter>(
    std::make_shared<xmetrics::Registry>(xmetrics::global_registry()),
    udp_transport
);
```

### Custom Histogram Buckets

```cpp
// Create a histogram with custom bucket boundaries
std::vector<double> buckets = {0.1, 0.5, 1.0, 2.5, 5.0, 10.0};
auto response_time = xmetrics::histogram(
    "http_response_time_seconds", 
    "HTTP response time in seconds",
    buckets
);
```

## Use with Grafana

XMetrics is designed to integrate seamlessly with Grafana dashboards:

1. Configure XMetrics to send data to your time-series database (InfluxDB, Prometheus, etc.)
2. Add your data source to Grafana
3. Create dashboards using metrics and tags defined in your application
4. Setup alerts based on thresholds, rates of change, etc.

## Thread Safety

All metrics in XMetrics are thread-safe by default. You can safely update metrics from multiple threads without additional synchronization.

## Performance Considerations

- Metrics are stored as atomic values for minimal overhead
- Reporting happens in a separate thread to avoid blocking
- Reporters can batch metrics to reduce network overhead
- Consider using UDP transport for very high-frequency metrics

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
