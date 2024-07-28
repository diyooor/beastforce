#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/config.hpp>
#include <boost/json/src.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>

#define BOOST_BEAST_ALLOW_DEPRECATED

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json;

void send_request(const std::string& host, const std::string& port, const std::string& target, const json& body, const std::string& session_id = "") {
    try {
        net::io_context ioc;

        // Create a resolver and query for the host
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve(host, port);

        // Create a socket and connect to the host
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        // Create a POST request
        http::request<http::string_body> req{http::verb::post, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_DEPRECATION_STRING);
        req.set(http::field::content_type, "application/json");
        req.body() = body.dump();
        req.prepare_payload();

        // Include session ID in the request headers if provided
        if (!session_id.empty()) {
            req.set("Session-ID", session_id);
        }

        // Send the request
        http::write(stream, req);

        // Buffer for the response
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the response
        http::read(stream, buffer, res);

        // Print the response
        std::cout << res << std::endl;

        // Gracefully close the socket
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void register_user(const std::string& username, const std::string& password) {
    json body;
    body["username"] = username;
    body["password"] = password;

    send_request("localhost", "8080", "/register", body);
}

std::string login_user(const std::string& username, const std::string& password) {
    json body;
    body["username"] = username;
    body["password"] = password;

    try {
        net::io_context ioc;

        // Create a resolver and query for the host
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve("localhost", "8080");

        // Create a socket and connect to the host
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        // Create a POST request
        http::request<http::string_body> req{http::verb::post, "/login", 11};
        req.set(http::field::host, "localhost");
        req.set(http::field::user_agent, BOOST_BEAST_DEPRECATION_STRING);
        req.set(http::field::content_type, "application/json");
        req.body() = body.dump();
        req.prepare_payload();

        // Send the request
        http::write(stream, req);

        // Buffer for the response
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the response
        http::read(stream, buffer, res);

        // Print the response
        std::cout << res << std::endl;

        // Parse the response body to get the session ID
        auto res_body = json::parse(beast::buffers_to_string(res.body().data()));
        std::string session_id = res_body["session_id"];

        // Gracefully close the socket
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);

        return session_id;
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return "";
    }
}
void request_protected_content(const std::string& session_id) {
    json body;
    body["session_id"] = session_id;
    send_request("localhost", "8080", "/protected", body, session_id);
}

int main() {
    register_user("test_user", "test_password");
    std::string session_id = login_user("test_user", "test_password");
    if (!session_id.empty()) {
        request_protected_content(session_id);
    }
    return 0;
}

