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

int main(int argc, char **argv) {
    std::string server_ip = (argc >= 2) ? argv[1] : LOCAL_HOST;
    int server_port = (argc >= 3) ? std::stoi(argv[2]) : DEFAULT_PORT;
    ServerConnection conn(server_ip, server_port);
    std::cout << "Commands: register <name> <password> | login <name> <password> <port> | logout | list | quit\n";

    while (conn.continued()) {
        std::cout << "> ";
        std::string command;
        if (!std::getline(std::cin, command))
            break;
        conn.handle_command(command);
    }

    std::cout << "Connection closed by server." << std::endl;
    return 0;
}

/* ===================================
   ServerConnection Implementation
   =================================== */

ServerConnection::ServerConnection(const std::string& server_ip, int server_port) : fd(-1), my_name(""), should_continue(true), listen_fd(-1), listen_port(0) {
    /* Create connection socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        err_exit("socket");

    /* Set up server address */
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
    server_addr.sin_port = htons(server_port);

    /* Connect to server */
    if (connect(fd, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(fd);
        err_exit("connect");
    }
    
    std::cout << "Connected to server at " << server_ip << ":" << server_port << std::endl;
}

ServerConnection::~ServerConnection() {
    close_listening_socket();  // Close P2P listening socket if open
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
}

void ServerConnection::handle_command(const std::string& command) {
    std::istringstream iss(command);
    std::string command_type;
    iss >> command_type;

    if (command_type == "register") {
        std::string name, password;
        iss >> name >> password;
        if (name.empty() || password.empty()) {
            std::cout << "Usage: register <name> <password>" << std::endl;
            return;
        }
        send_line(std::to_string(REGISTER) + " " + name + " " + password);
        std::string respond;
        if (recv_line(respond))
            std::cout << respond << std::endl;
    }
    else if (command_type == "login") {
        std::string name, password, port_str;
        iss >> name >> password >> port_str;
        if (name.empty() || password.empty() || port_str.empty()) {
            std::cout << "Usage: login <name> <password> <port>" << std::endl;
            return;
        }

        /* Check if port is a number */
        int port;
        try {
            size_t pos;
            port = std::stoi(port_str, &pos);
            if (pos != port_str.length()) {
                std::cout << "Error: Port must be a valid number" << std::endl;
                return;
            }
        }
        catch (const std::exception&) {
            std::cout << "Error: Port must be a valid number" << std::endl;
            return;
        }

        // Check port range
        if (port < 1024 || port > 65535) {
            std::cout << "Error: Port must be between 1024 and 65535" << std::endl;
            return;
        }
        
        // Try to create listening socket on the specified port
        if (!create_listening_socket(port)) {
            std::cout << "Error: Port " << port << " is not available (already in use or permission denied)" << std::endl;
            return;
        }

        send_line(std::to_string(LOGIN) + " " + name + " " + password + " " + port_str);
        std::string respond;
        if (recv_line(respond)) {
            std::cout << respond << std::endl;
            if (respond.rfind("Login Success!", 0) == 0)
                my_name = name;  // Only set local state after server confirms login success
            else
                close_listening_socket(); // Close listening socket if login failed
        }
    }
    else if (command_type == "logout") {
        if (my_name.empty()) {
            std::cout << "Error: You must login first" << std::endl;
            return;
        }
        send_line(std::to_string(LOGOUT) + " " + my_name);
        std::string respond;
        if (recv_line(respond)) {
            std::cout << respond << std::endl;
            /* Close listening socket after logout */
            if (respond.rfind("Logout Success!", 0) == 0) {
                close_listening_socket();
                my_name.clear();
            }
        }
    }
    else if (command_type == "list") {
        send_line(std::to_string(LIST));
        std::string respond;
        if (recv_line(respond))
            std::cout << respond << std::endl;
    }
    else if (command_type == "quit") {
        std::cout << "Goodbye!\n";
        should_continue = false;
    }   
    else if (!command_type.empty()) {
        send_line(std::to_string(UNKNOWN));
        std::string respond;
        if (recv_line(respond))
            std::cout << respond << std::endl;
    }
}

void ServerConnection::send_line(const std::string& s) {
    std::string line = s + "\n";
    ssize_t total_sent = 0;
    ssize_t len = line.length();
    while (total_sent < len) {
        ssize_t sent = send(fd, line.c_str() + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            switch (errno) {
                case EINTR: {
                    continue;
                }
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                {
                    usleep(1000);  // Wait 1ms
                    continue;
                }
                case EPIPE:
                case ECONNRESET:
                {
                    should_continue = false;
                    return;  // ← 改用 return
                }
                default: {
                    err_exit("send");
                }
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
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            switch (errno) {
                case EINTR: {
                    continue;
                }
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                {
                    usleep(1000);  // Wait 1ms
                    continue;
                }
                case ECONNRESET: {
                    should_continue = false;
                    return false;  // ← 改用 return
                }
                default: {
                    err_exit("recv");
                }
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

bool ServerConnection::create_listening_socket(int port) {
    // If there's already a listening socket, close it first
    close_listening_socket();
    
    // Create listening socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "Failed to create listening socket: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Set SO_REUSEADDR to allow quick restart
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set SO_REUSEADDR: " << strerror(errno) << std::endl;
        close(listen_fd);
        listen_fd = -1;
        return false;
    }
    
    // Bind to the port
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    addr.sin_port = htons(port);
    
    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind to port " << port << ": " << strerror(errno) << std::endl;
        close(listen_fd);
        listen_fd = -1;
        return false;
    }
    
    // Start listening
    if (listen(listen_fd, 5) < 0) {
        std::cerr << "Failed to listen on port " << port << ": " << strerror(errno) << std::endl;
        close(listen_fd);
        listen_fd = -1;
        return false;
    }
    
    listen_port = port;
    std::cout << "P2P listening socket created on port " << port << std::endl;
    return true;
}

void ServerConnection::close_listening_socket() {
    if (listen_fd >= 0) {
        std::cout << "Closing P2P listening socket on port " << listen_port << std::endl;
        close(listen_fd);
        listen_fd = -1;
        listen_port = 0;
    }
}

/* Helper functions */
inline void err_exit(const char *msg) {
    std::perror(msg);
    exit(EXIT_FAILURE);
}