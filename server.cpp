// =============================
// server.cpp
// Simple demo server: register/login/logout/list online users, get peer port for P2P chat
// Assumptions: localhost only, no encryption, minimal protocol.
// Build: g++ -std=c++17 -pthread server.cpp -o server
// Run:   ./server 8888
// =============================

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <csignal>
#include <cerrno>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <atomic>
#include "server.hpp"
#include "thread_pool.hpp"

std::atomic<bool> server_running(true);
std::unordered_map<std::string, User> users;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;
std::vector<int> active_clients;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char **argv) {
    unsigned short port = (argc >= 2) ? std::stoi(argv[1]) : DEFAULT_PORT;
    Server server(port);

    /* Block signals and then create worker threads */
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);   // Ctrl+C
    sigaddset(&signal_set, SIGTERM);  // "kill" command
    pthread_sigmask(SIG_BLOCK, &signal_set, nullptr);
    ThreadPool thread_pool(10);

    /* Register signal handler and then unblock signals */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    pthread_sigmask(SIG_UNBLOCK, &signal_set, nullptr);
    
    while (server_running) {
        int client_fd = server.accept_conn();
        if (client_fd < 0) {
            std::cerr << "Failed to accept connection, continuing to accept next one..." << std::endl;
            continue;
        }
        thread_pool.submit(client_fd);
    }

    thread_pool.stop();
    for (int fd : active_clients)
        shutdown(fd, SHUT_RD);

    std::cout << "Server closed successfully." << std::endl;
    return 0;
}

/* Signal handler */
void signal_handler(int sig) {
    if (sig == SIGINT)
        write(STDERR_FILENO, "\nReceived SIGINT (Ctrl+C)\n", 26);
    else if (sig == SIGTERM)
        write(STDERR_FILENO, "\nReceived SIGTERM\n", 18);
    server_running = false;
}

/* Helper functions */
inline void err_exit(const char *msg) {
    std::perror(msg);
    exit(EXIT_FAILURE);
}

/* ========================
   Server Implementation
   ======================== */

Server::Server(unsigned short p) : port(p), listen_fd(-1) {
    /* Establish welcome socket */
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // IPv4, TCP
        err_exit("socket");

    /* Set socket options (Avoid address reuse due to TIME WAIT) */
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        err_exit("setsockopt");

    /* Set server address structure */
    sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET; // IPv4
    listen_addr.sin_addr.s_addr = inet_addr(LOCAL_HOST); // Listen on localhost
    listen_addr.sin_port = htons(port);

    /* Bind the socket */
    if (bind(listen_fd, (sockaddr*)&listen_addr, sizeof(listen_addr)) < 0)
        err_exit("bind");

    /* Start listening (backlog = 10, meaning at most 10 waiting connections) */
    if (listen(listen_fd, 10) < 0)
        err_exit("listen");

    std::cout << "Server initialized and listening on " << LOCAL_HOST << ":" << port << std::endl;
}

Server::~Server() {
    if (listen_fd >= 0)
        close(listen_fd);
}

int Server::accept_conn() {
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (sockaddr*)&client_addr, &client_len);
    if (client_fd < 0)
        return -1;

    std::cout << "New client connected from " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << std::endl;
    return client_fd;
}

/* ===================================
   ClientConnection Implementation
   =================================== */

ClientConnection::ClientConnection(int client_fd) : fd(client_fd), logged_in_name("") {
    if (fd < 0) {
        std::perror("Invalid client_fd in ClientConnection constructor");
        pthread_exit(nullptr);
    }
        
    pthread_mutex_lock(&clients_mutex);
    active_clients.push_back(fd);
    pthread_mutex_unlock(&clients_mutex);
}

ClientConnection::~ClientConnection() {
    pthread_mutex_lock(&clients_mutex);
    active_clients.erase(std::remove(active_clients.begin(), active_clients.end(), fd), active_clients.end());
    pthread_mutex_unlock(&clients_mutex);

    if (!logged_in_name.empty()) {
        pthread_mutex_lock(&users_mutex);
        if (users.find(logged_in_name) != users.end()) {
            users[logged_in_name].online = false;
            users[logged_in_name].port = 0;
        }
        pthread_mutex_unlock(&users_mutex);
    }

    close(fd);
}

void ClientConnection::handle_command(const std::string& command) {
    std::istringstream iss(command);
    std::string command_type;
    iss >> command_type;
    
    switch (std::stoi(command_type)) {
        case REGISTER: {
            std::string name, password;
            iss >> name >> password;
            pthread_mutex_lock(&users_mutex);
            if (!logged_in_name.empty()) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR YouHaveToLogoutFirst");
            }
            else if (users.find(name) != users.end()) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR UserExists");
            }
            else {
                User new_user;
                new_user.password = password;
                users[name] = new_user;
                pthread_mutex_unlock(&users_mutex);
                send_line("Register Success!");
            }
            break;
        }
        
        case LOGIN: {
            std::string name, password; 
            unsigned short port;
            iss >> name >> password >> port;
            pthread_mutex_lock(&users_mutex);
            if (!logged_in_name.empty()) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR YouHaveToLogoutFirst");
            }
            else if (users.find(name) == users.end()) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR UserNotFound");
            }
            else if (users[name].password != password) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR WrongPassword");
            }
            else if (users[name].online) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR AlreadyOnline");
            }
            else {
                users[name].online = true;
                users[name].port = port;
                pthread_mutex_unlock(&users_mutex);
                logged_in_name = name;
                send_line("Login Success!");
            }
            break;
        }
        
        case LOGOUT: {
            std::string name;
            iss >> name;
            pthread_mutex_lock(&users_mutex);
            if (users.find(name) == users.end()) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR UserNotFound");
            }
            else if (!users[name].online) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR NotOnline");
            }
            else {
                users[name].online = false;
                users[name].port = 0;
                pthread_mutex_unlock(&users_mutex);
                logged_in_name = "";
                send_line("Logout Success!");
            }
            break;
        }
        
        case LIST: {
            pthread_mutex_lock(&users_mutex);
            if (logged_in_name.empty()) {
                pthread_mutex_unlock(&users_mutex);
                send_line("ERROR YouMustLoginFirst");
                break;
            }
            std::string response = "Online Users:";
            for (const auto& pair : users) {
                if (pair.second.online)
                    response += " " + pair.first + " " + std::to_string(pair.second.port);
            }
            pthread_mutex_unlock(&users_mutex);
            send_line(response);
            break;
        }
        
        default:
            send_line("ERROR UnknownCommand");
    }
}

void ClientConnection::send_line(const std::string& s) {
    std::string line = s + "\n";
    ssize_t total_sent = 0;
    ssize_t len = line.length();
    while (total_sent < len) {
        ssize_t sent = send(fd, line.c_str() + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            switch (errno) {
                case EINTR: { // Interrupted by signal
                    if (!server_running)
                        return;
                    continue;
                }
                case EAGAIN: // Send buffer full
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                {
                    usleep(1000);
                    continue;
                }
                default: { // Other errors
                    std::perror("send");
                    pthread_exit(nullptr);
                }
            }
        }
        total_sent += sent;
    }
    return;
}

bool ClientConnection::recv_line(std::string& out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            switch (errno) {
                case EINTR: {
                    if (!server_running)
                        return false;
                    continue;
                }
                case EAGAIN:
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                {
                    usleep(1000);
                    continue;
                }
                default: { // Other unexpected errors
                    std::perror("recv");
                    pthread_exit(nullptr);
                }
            }
        }
        else if (n == 0) // Connection should be closed or closed by peer
            return false;
        
        if (c == '\n')
            return true;
        out += c;
    }
}