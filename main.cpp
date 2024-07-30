#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
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
#include <atomic>
#include <string>
#include <fstream>
#include <sstream>
namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json; 

std::atomic<int> active_connections(0);
std::atomic<int> total_requests(0);
std::chrono::time_point<std::chrono::steady_clock> start_time = std::chrono::steady_clock::now();

class ClientService {
public:
    ClientService() : resolver_(ioc_), stream_(ioc_) {}

    std::string get(const std::string& host, const std::string& port, const std::string& target, int version = 11) {
        try {
            auto const results = resolver_.resolve(host, port);
            net::connect(stream_.socket(), results.begin(), results.end());
            http::request<http::string_body> req{http::verb::get, target, version};
            req.set(http::field::host, host);
            http::write(stream_, req);
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(stream_, buffer, res);
            beast::error_code ec;
            stream_.socket().shutdown(tcp::socket::shutdown_both, ec);
            if(ec && ec != beast::errc::not_connected)
                throw beast::system_error{ec};

            return beast::buffers_to_string(res.body().data());
        } catch (std::exception const& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return "";
        }
    }

private:
    net::io_context ioc_;
    tcp::resolver resolver_;
    beast::tcp_stream stream_;
};


class Session {
    private:
        int id;
        std::string session_id;
    public:
        void set_id(int id_) { id = id_; }
        void set_session_id(std::string session_id_) { session_id = session_id_; }
        std::string get_session_id() { return session_id; }
};

class User {
    private:
        int id;
        std::string username;
        std::string password;
        Session session;
    public:
        void set_id(int id_) { id = id_; }
        void set_username(std::string username_) { username = username_; }
        void set_password(std::string password_) { password = password_; }
        void set_session(Session session_) { session = session_; }
        int get_id() const { return id; }
        std::string get_username() const { return username; }
        std::string get_password() const { return password; }
        Session get_session() const { return session; }
        void invalidate_session() {
            session.set_session_id("");
        }
        void generate_session_id() {
            std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            std::mt19937 gen(static_cast<unsigned long>(time(0)));
            std::uniform_int_distribution<> dis(0, chars.size() - 1);

            std::string session_id;
            for (int i = 0; i < 16; ++i) {
                session_id += chars[dis(gen)];
            }
            session.set_session_id(session_id);
        }
};

class UserService {
    private:
        std::vector<User> users;
        std::mutex mtx;
    public:
        void add_user(User user) {
            users.emplace_back(user); 
            std::cout << user.get_id() << " " << user.get_username() << " " << user.get_password() << std::endl;
        }
        int get_users_size() const { return users.size(); } 

        bool validate_login(const std::string& username, const std::string& password) {
            std::lock_guard<std::mutex> lock(mtx);
            for (int i = 0; i < users.size(); i++) {
                if (users.at(i).get_username() == username && users.at(i).get_password() == password) {
                    users.at(i).generate_session_id();
                    Session temp = users.at(i).get_session();
                    std::cout << users.at(i).get_id() << " " << temp.get_session_id() << std::endl; 
                    return true;
                }
            }
            return false;
        }

        std::string get_session_id(const std::string& username) const {
            for (const auto& user : users) {
                if (user.get_username() == username) {
                    return user.get_session().get_session_id();
                }
            }
            return "";
        }        
        bool is_session_valid(const std::string& session_id) const {
            for (const auto& user : users) {
                if (user.get_session().get_session_id() == session_id) {
                    return true;
                }
            }
            return false;
        }
        bool invalidate_session(const std::string& session_id) {
            std::lock_guard<std::mutex> lock(mtx);
            for (auto& user : users) {
                if (user.get_session().get_session_id() == session_id) {
                    user.invalidate_session();
                    return true;
                }
            }
            return false;
        }
        std::vector<User>& get_users() { return users; }
        std::mutex& get_mutex() { return mtx; }
};

class Application {
public:
    Application() 
        : user_service_(std::make_shared<UserService>()), client_service_(std::make_shared<ClientService>()) {}

    std::shared_ptr<UserService> get_user_service() const { return user_service_; }
    std::shared_ptr<ClientService> get_client_service() const { return client_service_; }

private:
    std::shared_ptr<UserService> user_service_;
    std::shared_ptr<ClientService> client_service_;
};

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

template <class Body, class Allocator>
http::message_generator handle_request(beast::string_view doc_root, http::request<Body, http::basic_fields<Allocator>>&& req, std::shared_ptr<Application> app) {
    total_requests++;
    auto const res_ = [&req](http::status status, const std::string& body, const std::string& content_type = "application/json") {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::content_type, content_type);
        res.keep_alive(req.keep_alive());
        res.body() = body;
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
                json response;
                response["success"] = "true";
                return res_(http::status::ok, response.dump());
            } catch (const std::exception &e) {
                return res_(http::status::internal_server_error, e.what());
            }
        }
        if (req.target() == "/login") {
            try {
                json req_ = json::parse(req.body());
                auto user_service = app->get_user_service();
                if (user_service->validate_login(req_["username"], req_["password"])) {
                    std::string session_id = user_service->get_session_id(req_["username"]);
                    json response;
                    response["success"] = "true";
                    response["session_id"] = session_id;
                    return res_(http::status::ok, response.dump());
                } else {
                    json response;
                    response["success"] = "false";
                    response["error"] = "Invalid login";
                    return res_(http::status::unauthorized, response.dump());
                }
            } catch (const std::exception &e) {
                json response;
                response["success"] = "false";
                response["error"] = e.what();
                return res_(http::status::internal_server_error, response.dump());
            }
        }
        if (req.target() == "/protected") {
            try {
                json req_ = json::parse(req.body());
                auto user_service = app->get_user_service();
                if (!req_.contains("session_id") || req_["session_id"].is_null()) {
                    return res_(http::status::internal_server_error, "session_id is missing or null");
                }
                std::string session_id = req_["session_id"];
                if (user_service->is_session_valid(session_id)) {
                    json response;
                    response["success"] = "true";
                    response["session_id"] = session_id;
                    return res_(http::status::ok, response.dump());
                } else {
                    return res_(http::status::internal_server_error, "invalid session");
                }
            } catch (const std::exception &e) {
                return res_(http::status::internal_server_error, e.what());
            }
        }
        if (req.target() == "/password") {
            try {
                json req_ = json::parse(req.body());
                auto user_service = app->get_user_service();

                if (!req_.contains("session_id") || req_["session_id"].is_null()) {
                    return res_(http::status::bad_request, "session_id is missing or null");
                }

                std::string session_id = req_["session_id"];
                if (!user_service->is_session_valid(session_id)) {
                    return res_(http::status::unauthorized, "Invalid session");
                }

                std::string current_password = req_["current_password"];
                std::string new_password = req_["new_password"];

                std::lock_guard<std::mutex> lock(user_service->get_mutex());
                for (auto& user : user_service->get_users()) {
                    if (user.get_session().get_session_id() == session_id) {
                        if (user.get_password() != current_password) {
                            return res_(http::status::unauthorized, "Current password is incorrect");
                        }
                        user.set_password(new_password);
                        json response;
                        response["success"] = "true";
                        return res_(http::status::ok, response.dump());
                    }
                }
            } catch (const std::exception& e) {
                json response;
                response["success"] = "false";
                response["error"] = e.what();
                return res_(http::status::internal_server_error, response.dump());
            }
        }
        if (req.target() == "/logout") {
            try {
                json req_ = json::parse(req.body());
                auto user_service = app->get_user_service();
                if (!req_.contains("session_id") || req_["session_id"].is_null()) {
                    return res_(http::status::bad_request, "session_id is missing or null");
                }
                std::string session_id = req_["session_id"];
                if (user_service->invalidate_session(session_id)) {
                    json response;
                    response["success"] = "true";
                    return res_(http::status::ok, response.dump());
                } else {
                    return res_(http::status::unauthorized, "Invalid session");
                }
            } catch (const std::exception &e) {
                json response;
                response["success"] = "false";
                response["error"] = e.what();
                return res_(http::status::internal_server_error, response.dump());
            }
        }
    }

    if (req.method() != http::verb::get && req.method() != http::verb::head)
        return res_(http::status::bad_request, "Unknown HTTP-method", "text/html");

    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != beast::string_view::npos)
        return res_(http::status::bad_request, "Illegal request-target", "text/html");
    
    std::string path = path_cat(doc_root, req.target());
    if (req.method() == http::verb::get) {
        if (req.target().back() == '/')
           path.append("index.html");
        else if (req.target() == "/status") {
            json response;
            response["active_connections"] = active_connections.load();
            response["total_requests"] = total_requests.load();
            //response["cpu_usage"] = get_cpu_usage();
            //response["memory_usage"] = get_memory_usage();
            //response["uptime"] = get_uptime();
            return res_(http::status::ok, response.dump());
        }
        if (req.target() == "/external") {
            try {
                std::string host = "example.com";
                std::string port = "80";
                std::string target = "/path";
                auto client_service = app->get_client_service();
                std::string response = client_service->get(host, port, target);
                return res_(http::status::ok, response, "text/plain");
            } catch (const std::exception &e) {
                return res_(http::status::internal_server_error, e.what());
            }
        }
    }

    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);
    if (ec == beast::errc::no_such_file_or_directory) {
        std::string msg = std::string(req.target()) + " not found";
        return res_(http::status::not_found, msg, "text/html");
    }
    if (ec)
        return res_(http::status::internal_server_error, ec.message(), "text/html"); 

    auto const size = body.size();

    if (req.method() == http::verb::head) {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::content_type, mime_type(path));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return res;
    }

    http::response<http::file_body> res{std::piecewise_construct, std::make_tuple(std::move(body)), std::make_tuple(http::status::ok, req.version())};
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

    ~session() {}

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

