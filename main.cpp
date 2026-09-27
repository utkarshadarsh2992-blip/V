#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

constexpr std::size_t MAX_REQUEST_BODY = 1U << 20;
constexpr std::size_t MAX_RESPONSE_BODY = 2U << 20;

struct RequestInput {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct ResponseOutput {
    long status_code = 0;
    std::map<std::string, std::vector<std::string>> headers;
    std::string body;
    bool truncated = false;
};

struct LoopOutput {
    int requested = 0;
    int completed = 0;
    std::vector<ResponseOutput> results;
    std::vector<std::string> errors;
};

void to_json(json& out, const ResponseOutput& value) {
    out = json{{"status_code", value.status_code}, {"headers", value.headers},
               {"body", value.body}, {"truncated", value.truncated}};
}

void to_json(json& out, const LoopOutput& value) {
    out = json{{"requested", value.requested}, {"completed", value.completed},
               {"results", value.results}};
    if (!value.errors.empty()) out["errors"] = value.errors;
}

std::string upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return value;
}

bool allowed_method(const std::string& method) {
    static const std::set<std::string> methods = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};
    return methods.count(method) != 0;
}

std::string host_from_url(const std::string& url) {
    static const std::regex pattern(R"(^https?://([^/:?#]+)(?::[0-9]+)?(?:[/?#].*)?$)",
                                    std::regex::icase);
    std::smatch match;
    if (!std::regex_match(url, match, pattern)) return {};
    return match[1].str();
}

bool private_or_local_host(const std::string& host) {
    const std::string lower = [&] {
        std::string result = host;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }();
    if (lower == "localhost" || (lower.size() > 10 && lower.rfind(".localhost") == lower.size() - 10)) return true;

    in_addr ipv4{};
    if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
        const auto value = ntohl(ipv4.s_addr);
        return (value >> 24) == 10 || (value >> 20) == ((172 << 4) | 1) ||
               (value >> 16) == ((192 << 8) | 168) || (value >> 24) == 127 ||
               (value >> 28) == 0;
    }
    return false;
}

RequestInput parse_request_input(const json& input) {
    if (!input.is_object() || !input.contains("url") || !input["url"].is_string())
        throw std::invalid_argument("url is required");

    RequestInput request;
    request.url = input["url"].get<std::string>();
    if (input.contains("method")) request.method = upper(input["method"].get<std::string>());
    if (!allowed_method(request.method))
        throw std::invalid_argument("method must be one of GET, POST, PUT, PATCH, DELETE, or OPTIONS");

    const auto host = host_from_url(request.url);
    if (host.empty()) throw std::invalid_argument("url must be an absolute HTTP or HTTPS URL");
    if (private_or_local_host(host)) throw std::invalid_argument("requests to private or local addresses are not allowed");

    if (input.contains("headers")) {
        if (!input["headers"].is_object()) throw std::invalid_argument("headers must be an object");
        for (auto it = input["headers"].begin(); it != input["headers"].end(); ++it) {
            if (!it.value().is_string()) throw std::invalid_argument("header values must be strings");
            if (upper(it.key()) == "HOST" || upper(it.key()) == "CONTENT-LENGTH") continue;
            request.headers[it.key()] = it.value().get<std::string>();
        }
    }
    if (input.contains("body") && !input["body"].is_null()) {
        request.body = input["body"].is_string() ? input["body"].get<std::string>() : input["body"].dump();
        if (request.headers.find("Content-Type") == request.headers.end()) request.headers["Content-Type"] = "application/json";
    }
    return request;
}

struct CurlContext {
    std::string body;
    std::map<std::string, std::vector<std::string>> headers;
    bool truncated = false;
};

size_t body_callback(char* data, size_t size, size_t count, void* userdata) {
    auto* context = static_cast<CurlContext*>(userdata);
    const std::size_t bytes = size * count;
    const std::size_t remaining = MAX_RESPONSE_BODY > context->body.size() ? MAX_RESPONSE_BODY - context->body.size() : 0;
    context->body.append(data, std::min(bytes, remaining));
    if (bytes > remaining) context->truncated = true;
    return bytes;
}

size_t header_callback(char* data, size_t size, size_t count, void* userdata) {
    auto* context = static_cast<CurlContext*>(userdata);
    const std::string line(data, size * count);
    const auto separator = line.find(':');
    if (separator != std::string::npos) {
        std::string key = line.substr(0, separator);
        std::string value = line.substr(separator + 1);
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.pop_back();
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());
        context->headers[key].push_back(value);
    }
    return size * count;
}

ResponseOutput execute_request(const RequestInput& request) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("could not initialize curl");
    CurlContext context;
    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &context);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cpp-http-bot/1.0");
    if (!request.body.empty()) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.c_str());

    curl_slist* headers = nullptr;
    for (const auto& [key, value] : request.headers) headers = curl_slist_append(headers, (key + ": " + value).c_str());
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    const CURLcode result = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK) throw std::runtime_error(curl_easy_strerror(result));
    return ResponseOutput{status, std::move(context.headers), std::move(context.body), context.truncated};
}

json handle_loop(const json& input) {
    if (input.contains("count") && !input["count"].is_number_integer()) throw std::invalid_argument("count must be an integer");
    const int count = input.value("count", 10);
    if (count < 1 || count > 1000) throw std::invalid_argument("count must be between 1 and 1000");
    const RequestInput request = parse_request_input(input);
    const bool concurrent = input.value("concurrent", true);
    const int concurrency = std::max(1, std::min(count, input.value("concurrency", count)));

    LoopOutput output;
    output.requested = count;
    std::vector<std::future<ResponseOutput>> futures;
    std::vector<std::string> errors(count);
    std::vector<ResponseOutput> results(count);
    std::vector<bool> succeeded(count, false);

    auto run_one = [&](int index) {
        try {
            results[index] = execute_request(request);
            succeeded[index] = true;
        } catch (const std::exception& ex) {
            errors[index] = "request " + std::to_string(index + 1) + ": " + ex.what();
        }
    };

    if (!concurrent) {
        for (int i = 0; i < count; ++i) run_one(i);
    } else {
        for (int start = 0; start < count; start += concurrency) {
            futures.clear();
            const int end = std::min(count, start + concurrency);
            for (int i = start; i < end; ++i) futures.emplace_back(std::async(std::launch::async, [&, i] { run_one(i); return ResponseOutput{}; }));
            for (auto& future : futures) future.get();
        }
    }
    for (int i = 0; i < count; ++i) {
        if (succeeded[i]) { output.results.push_back(std::move(results[i])); ++output.completed; }
        else output.errors.push_back(errors[i]);
    }
    return output;
}

http::response<http::string_body> json_response(http::status status, const json& payload) {
    http::response<http::string_body> response{status, 11};
    response.set(http::field::content_type, "application/json");
    response.body() = payload.dump();
    response.prepare_payload();
    return response;
}

void session(tcp::socket socket) {
    beast::flat_buffer buffer;
    try {
        http::request_parser<http::string_body> parser;
        parser.body_limit(MAX_REQUEST_BODY);
        http::read(socket, buffer, parser);
        auto request = parser.release();
        http::response<http::string_body> response;
        if (request.method() == http::verb::get && request.target() == "/health") {
            response = json_response(http::status::ok, {{"status", "ok"}});
        } else if (request.method() == http::verb::post && (request.target() == "/bot/request" || request.target() == "/bot/loop")) {
            try {
                const json input = json::parse(request.body());
                const json output = request.target() == "/bot/loop" ? handle_loop(input) : json(execute_request(parse_request_input(input)));
                response = json_response(http::status::ok, output);
            } catch (const std::exception& ex) {
                response = json_response(http::status::bad_request, {{"error", ex.what()}});
            }
        } else {
            response = json_response(http::status::not_found, {{"error", "route not found"}});
        }
        response.keep_alive(false);
        http::write(socket, response);
        beast::error_code ignored;
        socket.shutdown(tcp::socket::shutdown_send, ignored);
    } catch (const std::exception& ex) {
        std::cerr << "session error: " << ex.what() << '\n';
    }
}

int main() {
    const char* port_text = std::getenv("PORT");
    const unsigned short port = port_text ? static_cast<unsigned short>(std::stoi(port_text)) : 8080;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    try {
        asio::io_context context;
        tcp::acceptor acceptor(context, {tcp::v4(), port});
        std::cout << "C++ HTTP bot listening on http://0.0.0.0:" << port << '\n';
        for (;;) {
            tcp::socket socket(context);
            acceptor.accept(socket);
            std::thread(session, std::move(socket)).detach();
        }
    } catch (const std::exception& ex) {
        std::cerr << "server error: " << ex.what() << '\n';
        curl_global_cleanup();
        return 1;
    }
}
