#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include "client.hpp"
#include "ui_utils.hpp"

int main(int argc, char **argv) {
    std::string server_ip = (argc >= 2) ? argv[1] : LOCAL_HOST;
    int server_port = (argc >= 3) ? std::stoi(argv[2]) : DEFAULT_PORT;
    ServerConnection conn(server_ip, server_port);

    UI::print_banner("CHAT CLIENT");        
    UI::print_line();
    UI::print_info("Available commands:");
    std::cout << Color::DIM << "  register <name> <password>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  login <name> <password> <port>" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  logout" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  list" << Color::RESET << std::endl;
    std::cout << Color::DIM << "  quit" << Color::RESET << std::endl;
    UI::print_line();
    std::cout << std::endl;

    while (conn.continued()) {
        UI::print_prompt();
        std::string command;
        if (!std::getline(std::cin, command))
            break;
        conn.handle_command(command);
    }

    UI::print_warning("Connection closed by server.");
    return 0;
}

/* ===================================
   ServerConnection Implementation
   =================================== */

ServerConnection::ServerConnection(const std::string& server_ip, int server_port) : server_fd(-1), my_name(""), should_continue(true), listen_fd(-1), listen_port(0) {
    /* Create connection socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
        ERR_EXIT("socket");

    /* Set up server address */
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
    server_addr.sin_port = htons(server_port);

    /* Connect to server */
    if (connect(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        ERR_EXIT("connect");
    
    UI::print_success("Connected to server at " + server_ip + ":" + std::to_string(server_port));
}

ServerConnection::~ServerConnection() {
    if (server_fd >= 0)
        close(server_fd);
    if (listen_fd >= 0)
        close_listening_socket();
}

bool ServerConnection::create_listening_socket(int port) {
    /* Create listening socket */
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
        ERR_EXIT("socket");
    
    /* Set socket options (Avoid address reuse due to TIME WAIT) */
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        ERR_EXIT("setsockopt");
    
    /* Set address structure */
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    addr.sin_port = htons(port);
    
    /* Bind to the port */
    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        listen_fd = -1;
        return false;
    }
    
    /* Start listening */
    if (listen(listen_fd, 5) < 0)
        ERR_EXIT("listen");
    
    listen_port = port;
    UI::print_local_message("P2P listening socket created on port " + std::to_string(port));
    return true;
}

void ServerConnection::handle_command(const std::string& command) {
    std::string error_msgs[] = {"User already exists", "User not found", "Wrong password", "User already online", "User not online", "You must login first", "You must logout first", "Unknown command"};
    std::istringstream iss(command);
    std::string command_type;
    iss >> command_type;

    if (command_type == "register") {
        std::string name, password;
        iss >> name >> password;
        if (name.empty() || password.empty()) {
            UI::print_error("Usage: register <name> <password>");
            return;
        }
        send_line(std::to_string(REGISTER) + " " + name + " " + password);
        std::string respond;
        if (recv_line(respond)) {
            std::istringstream iss(respond);
            int response_code;
            iss >> response_code;
            if (response_code == SUCCESS)
                UI::print_success("Register Success!");
            else {
                int error_code;
                iss >> error_code;
                UI::print_error(error_msgs[error_code]);
            }
        }
    }
    else if (command_type == "login") {
        std::string name, password, port_str;
        iss >> name >> password >> port_str;
        if (name.empty() || password.empty() || port_str.empty()) {
            UI::print_error("Usage: login <name> <password> <port>");
            return;
        }

        /* Check if port is a number */
        int port;
        try {
            size_t pos;
            port = std::stoi(port_str, &pos);
            if (pos != port_str.length()) {
                UI::print_error("Port must be a valid number");
                return;
            }
        } catch (const std::exception&) {
            UI::print_error("Port must be a valid number");
            return;
        }

        /* Check port range */
        if (port < 1024 || port > 65535) {
            UI::print_error("Port must be between 1024 and 65535");
            return;
        }

        /* Try to create listening socket on the specified port */
        if (listen_fd >= 0)
            close_listening_socket();
        if (!create_listening_socket(port)) {
            UI::print_error("Port " + std::to_string(port) + " is not available (already in use or permission denied)");
            return;
        }

        send_line(std::to_string(LOGIN) + " " + name + " " + password + " " + port_str);
        std::string respond;
        if (recv_line(respond)) {
            std::istringstream iss(respond);
            int response_code;
            iss >> response_code;
            if (response_code == SUCCESS) {
                UI::print_success("Login Success!");
                my_name = name;
            }
            else {
                int error_code;
                iss >> error_code;
                UI::print_error(error_msgs[error_code]);
                close_listening_socket();
            }
        }
    }
    else if (command_type == "logout") {
        if (my_name.empty()) {
            UI::print_error("You must login first");
            return;
        }
        send_line(std::to_string(LOGOUT) + " " + my_name);
        std::string respond;
        if (recv_line(respond)) {
            std::istringstream iss(respond);
            int response_code;
            iss >> response_code;
            if (response_code == SUCCESS) {
                UI::print_success("Logout Success!");
                close_listening_socket();
                my_name.clear();
            }
            else {
                int error_code;
                iss >> error_code;
                UI::print_error(error_msgs[error_code]);
            }
        }
    }
    else if (command_type == "list") {
        send_line(std::to_string(LIST));
        std::string respond;
        if (recv_line(respond)) {
            std::istringstream iss(respond);
            int response_code;
            iss >> response_code;
            if (response_code == SUCCESS) {
                std::string name;
                int port;
                std::string output = "Online Users:";
                while (iss >> name >> port)
                    output += " " + name + "-" + std::to_string(port);
                UI::print_server_message(output);
            }
            else {
                int error_code;
                iss >> error_code;
                UI::print_error(error_msgs[error_code]);
            }
        }
    }
    else if (command_type == "quit") {
        UI::print_info("Goodbye!");
        should_continue = false;
    }   
    else if (!command_type.empty()) {
        send_line(std::to_string(UNKNOWN));
        std::string respond;
        if (recv_line(respond)) {
            std::istringstream iss(respond);
            int response_code;
            iss >> response_code;
            if (response_code == ERROR) {
                int error_code;
                iss >> error_code;
                UI::print_error(error_msgs[error_code]);
            }
        }
    }
}

void ServerConnection::send_line(const std::string& s) {
    std::string line = s + "\n";
    ssize_t total_sent = 0;
    ssize_t len = line.length();
    while (total_sent < len) {
        ssize_t sent = send(server_fd, line.c_str() + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                case EPIPE:
                case ECONNRESET:
                    should_continue = false;
                    return;
                default:
                    ERR_EXIT("send");
            }
        }
        total_sent += sent;
    }
    return;
}

bool ServerConnection::recv_line(std::string& out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = recv(server_fd, &c, 1, 0);
        if (n < 0) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                case ECONNRESET:
                    should_continue = false;
                    return false;
                default:
                    ERR_EXIT("recv");
            }
        }
        else if (n == 0) { // Connection closed by server
            should_continue = false;
            return false;
        }
        
        if (c == '\n')
            return true;
        out += c;
    }
}

void ServerConnection::close_listening_socket() {
    UI::print_local_message("Closing P2P listening socket on port " + std::to_string(listen_port));
    close(listen_fd);
    listen_fd = -1;
    listen_port = 0;
}

void ServerConnection::ERR_EXIT(const char *msg) {
    std::perror(msg);
    if (server_fd >= 0)
        close(server_fd);
    if (listen_fd >= 0)
        close_listening_socket();
    exit(EXIT_FAILURE);
}