#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/config.hpp>
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
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve(host, port);
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        http::request<http::string_body> req{http::verb::post, target, 11};
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_DEPRECATION_STRING);
        req.set(http::field::content_type, "application/json");
        req.body() = body.dump();
        req.prepare_payload();

        if (!session_id.empty()) {
            req.set("Session-ID", session_id);
        }

        http::write(stream, req);
        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        http::read(stream, buffer, res);

        std::cout << res << std::endl;

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
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve("localhost", "8080");
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        http::request<http::string_body> req{http::verb::post, "/login", 11};
        req.set(http::field::host, "localhost");
        req.set(http::field::user_agent, BOOST_BEAST_DEPRECATION_STRING);
        req.set(http::field::content_type, "application/json");
        req.body() = body.dump();
        req.prepare_payload();

        http::write(stream, req);
        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        http::read(stream, buffer, res);
        std::cout << res << std::endl;

        auto res_body = json::parse(beast::buffers_to_string(res.body().data()));
        std::string session_id = res_body["session_id"];

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

void get_server_status() {
    try {
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve("localhost", "8080");
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        http::request<http::empty_body> req{http::verb::get, "/status", 11};
        req.set(http::field::host, "localhost");
        req.set(http::field::user_agent, BOOST_BEAST_DEPRECATION_STRING);
        http::write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        http::read(stream, buffer, res);

        std::cout << res << std::endl;

        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void request_index_content(const std::string& session_id) {
    try {
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve("localhost", "8080");
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        http::request<http::empty_body> req{http::verb::get, "/", 11};
        req.set(http::field::host, "localhost");
        req.set(http::field::user_agent, BOOST_BEAST_DEPRECATION_STRING);

        if (!session_id.empty()) {
            req.set("Session-ID", session_id);
        }

        http::write(stream, req);
        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        http::read(stream, buffer, res);

        std::cout << res << std::endl;
        std::string body = beast::buffers_to_string(res.body().data());
        //std::cout << "Response Body: " << body << std::endl;
        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    register_user("test_user", "test_password");
    std::string session_id = login_user("test_user", "test_password");
    if (!session_id.empty()) {
        request_protected_content(session_id);
        //request_index_content(session_id);
    }
    get_server_status();
    return 0;
}

