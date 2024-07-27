#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/config.hpp>
#include <boost/json/src.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <unordered_map>
#include <random>
#include <ctime>
#include <nlohmann/json.hpp>
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json; 

struct User {
    private:
        int id;
        std::string username;
        std::string password;
    public:
        void set_id(int id_) { id = id_; }
        void set_username(std::string username_) { username = username_; }
        void set_password(std::string password_) { password = password_; }
        std::string get_username() { return username; }
        std::string get_password() { return password; }
        int get_id() { return id; }
};

class UserService {
    private:
        std::vector<User> users;
    public:
        void add_user(User user) { 
            users.emplace_back(user); 
            std::cout << "add_user\n id: " << user.get_id() << " " << user.get_username() << " " << user.get_password()  << std::endl;
        }
        int get_users_size() { return users.size(); }

        bool validate_login(const std::string username, const std::string password) {
            for (int i = 0; i < users.size() + 1; i++) {
                if (users.at(i).get_username() == username) {
                    return true;
                }
            }
            return false;
        }
};

class Application {
    private:
        std::shared_ptr<UserService> user_service;
    public:
        Application() : user_service(std::make_shared<UserService>()) {
            std::cout << "Application() constructor" << std::endl;
        }
        std::shared_ptr<UserService> get_user_service() const { return user_service; }
        virtual ~Application() = default;
};


// Determine MIME type based on file extension
beast::string_view mime_type(beast::string_view path) {
    using beast::iequals;
    auto const ext = [&path] {
        auto const pos = path.rfind(".");
        if (pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();

    if (iequals(ext, ".htm") || iequals(ext, ".html") || iequals(ext, ".php")) return "text/html";
    if (iequals(ext, ".css")) return "text/css";
    if (iequals(ext, ".txt")) return "text/plain";
    if (iequals(ext, ".js")) return "application/javascript";
    if (iequals(ext, ".json")) return "application/json";
    if (iequals(ext, ".xml")) return "application/xml";
    if (iequals(ext, ".swf")) return "application/x-shockwave-flash";
    if (iequals(ext, ".flv")) return "video/x-flv";
    if (iequals(ext, ".png")) return "image/png";
    if (iequals(ext, ".jpe") || iequals(ext, ".jpeg") || iequals(ext, ".jpg")) return "image/jpeg";
    if (iequals(ext, ".gif")) return "image/gif";
    if (iequals(ext, ".bmp")) return "image/bmp";
    if (iequals(ext, ".ico")) return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff") || iequals(ext, ".tif")) return "image/tiff";
    if (iequals(ext, ".svg") || iequals(ext, ".svgz")) return "image/svg+xml";

    return "application/text";
}

// Concatenate base and path, handling platform-specific path separators
    std::string
path_cat(
        beast::string_view base,
        beast::string_view path)
{
    if(base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for(auto& c : result)
        if(c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if(result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}



// Handle HTTP requests and generate appropriate responses
template <class Body, class Allocator>
http::message_generator handle_request(beast::string_view doc_root, http::request<Body, http::basic_fields<Allocator>>&& req, std::shared_ptr<Application> app) {
    std::map<std::string, http::status> statusMap = {
        {"bad", http::status::bad_request},
        {"not_found", http::status::not_found},
        {"server_error", http::status::internal_server_error},
        {"ok_request", http::status::ok}};
    auto const res_map = [&req, &statusMap](std::string which,
            beast::string_view str) {
        auto status = statusMap[which];
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::server, BOOST_BEAST_DEPRECATION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(str);
        res.prepare_payload();
        return res;
    };    
    if (req.method() == http::verb::post) {
        if (req.target() == "/register") {
            try {
                json req_ = json::parse(req.body());
                User user_;
                user_.set_username(req_["username"]);
                user_.set_password(req_["password"]);
                auto user_service = app->get_user_service();
                user_.set_id(user_service->get_users_size()); 
                user_service->add_user(user_);
                return res_map("ok_request", "User registered successfully");
            } catch (const std::exception &e) {
                return res_map("server_error", e.what());
            }
        }
        if (req.target() == "/login") {
            try {
                json req_ = json::parse(req.body());
                auto user_service = app->get_user_service();
                if(user_service->validate_login(req_["username"], req_["password"]))
                    return res_map("ok_request", "user logged in successfully");
                else
                    return res_map("server_error", "invalid login");

            } catch (const std::exception &e) {
                return res_map("server_error", e.what());
            }
        }
    }

    if (req.method() != http::verb::get && req.method() != http::verb::head)
        return res_map("bad_request", "Unknown HTTP-method");

    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != beast::string_view::npos)
        return res_map("bad_request", "Illegal request-target");
    std::string path = path_cat(doc_root, req.target());
    if (req.method() == http::verb::get) {
        if (req.target().back() == '/')
            path.append("index.html");  
    }

    beast::error_code ec;
    http::file_body::value_type body;
    std::string msg = "";
    body.open(path.c_str(), beast::file_mode::scan, ec);
    if (ec == beast::errc::no_such_file_or_directory) {
        msg = std::string(req.target()) + " not found";
        return res_map("not_found", msg);
    }
    if (ec)
        return res_map("server_error", ec.message()); 

    auto const size = body.size();

    if (req.method() == http::verb::head) {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_DEPRECATION_STRING);
        res.set(http::field::content_type, mime_type(path));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return res;
    }

    http::response<http::file_body> res{std::piecewise_construct, std::make_tuple(std::move(body)), std::make_tuple(http::status::ok, req.version())};
    res.set(http::field::server, BOOST_BEAST_DEPRECATION_STRING);
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    res.keep_alive(req.keep_alive());
    return res;
}


// Log errors
void fail(beast::error_code ec, char const* what) {
    std::cerr << what << ": " << ec.message() << "\n";
}

// Handle an HTTP session
class session : public std::enable_shared_from_this<session> {
    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    std::shared_ptr<std::string const> doc_root_;
    http::request<http::string_body> req_;
    std::shared_ptr<Application> app_;
    public:
    session(tcp::socket&& socket, std::shared_ptr<std::string const> const& doc_root, std::shared_ptr<Application> app)
        : stream_(std::move(socket)), doc_root_(doc_root), app_(app) {}

    void run() {
        net::dispatch(stream_.get_executor(), beast::bind_front_handler(&session::do_read, shared_from_this()));
    }

    private:
    void do_read() {
        req_ = {};
        stream_.expires_after(std::chrono::seconds(30));
        http::async_read(stream_, buffer_, req_, beast::bind_front_handler(&session::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec == http::error::end_of_stream)
            return do_close();

        if (ec)
            return fail(ec, "read");

        send_response(handle_request(*doc_root_, std::move(req_), app_));
    }

    void send_response(http::message_generator&& msg) {
        bool keep_alive = msg.keep_alive();
        beast::async_write(stream_, std::move(msg), beast::bind_front_handler(&session::on_write, shared_from_this(), keep_alive));
    }

    void on_write(bool keep_alive, beast::error_code ec, std::size_t) {
        if (ec)
            return fail(ec, "write");

        if (!keep_alive)
            return do_close();

        do_read();
    }

    void do_close() {
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
    }
};

// Listen for incoming connections
class listener : public std::enable_shared_from_this<listener> {
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;
    std::shared_ptr<Application> app_;
    public:
    listener(net::io_context& ioc, tcp::endpoint endpoint, std::shared_ptr<std::string const> const& doc_root, std::shared_ptr<Application> app)
        : ioc_(ioc), acceptor_(net::make_strand(ioc)), doc_root_(doc_root), app_(app) {
            beast::error_code ec;
            acceptor_.open(endpoint.protocol(), ec);
            if (ec) { fail(ec, "open"); return; }

            acceptor_.set_option(net::socket_base::reuse_address(true), ec);
            if (ec) { fail(ec, "set_option"); return; }

            acceptor_.bind(endpoint, ec);
            if (ec) { fail(ec, "bind"); return; }

            acceptor_.listen(net::socket_base::max_listen_connections, ec);
            if (ec) { fail(ec, "listen"); return; }
        }

    void run() {
        do_accept();
    }

    private:
    void do_accept() {
        acceptor_.async_accept(net::make_strand(ioc_), beast::bind_front_handler(&listener::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            fail(ec, "accept");
            return;
        }
        std::make_shared<session>(std::move(socket), doc_root_, app_)->run();
        do_accept();
    }
};

// Main function to start the server
int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: http-server-async <address> <port> <doc_root> <threads>\n"
            << "Example:\n"
            << "    http-server-async 0.0.0.0 8080 . 1\n";
        return EXIT_FAILURE;
    }

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const doc_root = std::make_shared<std::string>(argv[3]);
    auto const threads = std::max<int>(1, std::atoi(argv[4]));
    auto const app = std::make_shared<Application>();
    net::io_context ioc{threads};

    std::make_shared<listener>(ioc, tcp::endpoint{address, port}, doc_root, app)->run();

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });

    ioc.run();

    return EXIT_SUCCESS;
}

