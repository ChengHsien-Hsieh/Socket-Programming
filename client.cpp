// =============================
// client.cpp
// Simple demo client: register/login/logout/list
// Build: g++ -std=c++17 client.cpp -o client
// Run:   ./client 127.0.0.1 8888
// =============================

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
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
    return 0;
}

/* ===================================
   ServerConnection Implementation
   =================================== */

ServerConnection::ServerConnection(const std::string& server_ip, int server_port) : fd(-1), my_name(""), quit_requested(false) {
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
        std::string name, password;
        int port;
        iss >> name >> password >> port;
        if (name.empty() || password.empty() || iss.fail()) {
            std::cout << "Usage: login <name> <password> <port>" << std::endl;
            iss.clear();
            return;
        }

        if (port < 1024 || port > 65535) {
            std::cout << "Error: Port must be between 1024 and 65535" << std::endl;
            return;
        }

        my_name = name;
        send_line(std::to_string(LOGIN) + " " + name + " " + password + " " + std::to_string(port));
        std::string respond;
        if (recv_line(respond))
            std::cout << respond << std::endl;
    }
    else if (command_type == "logout") {
        if (my_name.empty()) {
            std::cout << "Error: You must login first" << std::endl;
            return;
        }
        send_line(std::to_string(LOGOUT) + " " + my_name);
        std::string respond;
        if (recv_line(respond))
            std::cout << respond << std::endl;
    }
    else if (command_type == "list") {
        send_line(std::to_string(LIST));
        std::string respond;
        if (recv_line(respond))
            std::cout << respond << std::endl;
    }
    else if (command_type == "quit") {
        std::cout << "Goodbye!\n";
        quit_requested = true;
    }
    else if (!command_type.empty()) {
        std::cout << "Unknown command\n";
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
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                default:
                    err_exit("send");
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
                case EINTR:
                    continue;
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000);  // Wait 1ms
                    continue;
                default:
                    err_exit("recv");
            }
        }
        else if (n == 0) // Connection closed by server
            return false;
        
        if (c == '\n')
            return true;
        out += c;
    }
}

/* Helper functions */
inline void err_exit(const char *msg) {
    std::perror(msg);
    exit(EXIT_FAILURE);
}