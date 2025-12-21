#include "server.hpp"
#include "thread_pool.hpp"
#include "ui_utils.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <atomic>

/* Global variables */
std::atomic<bool> receive_signal(false);
std::unordered_map<std::string, User> users;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;
std::vector<int> conn_fds;
pthread_mutex_t conn_fds_mutex = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char **argv) {
    UI::print_banner("CHAT SERVER");
    
    unsigned short port = (argc >= 2) ? std::stoi(argv[1]) : DEFAULT_PORT;
    Server server(port);

    /* Block signals and then create worker threads */
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);   // Ctrl+C
    sigaddset(&signal_set, SIGTERM);  // "kill" command
    pthread_sigmask(SIG_BLOCK, &signal_set, nullptr);
    ThreadPool thread_pool(NUM_THREADS, handle_client);

    /* Register signal handler and then unblock signals */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    pthread_sigmask(SIG_UNBLOCK, &signal_set, nullptr);

    /* Print server ready message */
    UI::print_line();
    UI::print_server_status("Server is ready and waiting for connections...");
    UI::print_line();
    std::cout << std::endl;

    while (!receive_signal) {
        int client_fd = server.accept_conn();
        if (client_fd < 0)
            continue; // Accept failed, retry
        thread_pool.submit(client_fd);
    }

    thread_pool.shutdown(); // Close pending connections
    for (int fd : conn_fds)
        shutdown(fd, SHUT_RD); // Close connection blocked in "recv" by client
    
    UI::print_warning("Server closed successfully.");
    return 0;
}

/* Signal handler */
void signal_handler(int sig) {
    std::string msg = "Received signal: " + std::to_string(sig) + "\n";
    write(STDERR_FILENO, msg.c_str(), msg.size());
    receive_signal = true;
}

/* Worker thread function */
void handle_client(int client_fd, std::atomic<bool>* shutdown_flag) {
    ClientConnection conn(client_fd);
    std::string command;
    while (conn.recv_line(command) && !(*shutdown_flag))
        conn.handle_command(command);
}

/* ========================
   Server Implementation
   ======================== */

Server::Server(unsigned short p) : port(p) {
    /* Establish welcome socket */
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // IPv4, TCP
        ERR_EXIT("socket");

    /* Set socket options (Avoid address reuse due to TIME WAIT) */
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        ERR_EXIT("setsockopt");

    /* Set server address structure */
    sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET; // IPv4
    listen_addr.sin_addr.s_addr = inet_addr(LOCAL_HOST); // Listen on localhost
    listen_addr.sin_port = htons(port);

    /* Bind the socket */
    if (bind(listen_fd, (sockaddr*)&listen_addr, sizeof(listen_addr)) < 0)
        ERR_EXIT("bind");

    /* Start listening (backlog = 10, meaning at most 10 waiting connections) */
    if (listen(listen_fd, BACKLOG) < 0)
        ERR_EXIT("listen");

    UI::print_success("Server initialized and listening on " + std::string(LOCAL_HOST) + ":" + std::to_string(port));
}

Server::~Server() {
    close_server();
}

int Server::accept_conn() {
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        switch (errno) {
            case EINTR: // Interrupted by signals (Ctrl+C, kill, etc.)
                return -1;
            case ECONNABORTED: // Connection aborted by peer
                UI::print_warning("Connection aborted by peer, continuing...");
                return -1;
            case EMFILE:  // Per-process file descriptor limit
            case ENFILE:  // System-wide file descriptor limit
                UI::print_error("Too many open files, retrying in 1 second...");
                sleep(1);
                return -1;
            case EPROTO:      // Protocol error
            case ENETDOWN:    // Network is down
            case ENOPROTOOPT: // Protocol not available
            case EHOSTDOWN:   // Host is down
            case EHOSTUNREACH: // Host is unreachable
            case ENETUNREACH:  // Network unreachable
            case EAGAIN:      // Non-blocking mode, no connections
                UI::print_warning("Recoverable error in accept: " + std::string(strerror(errno)));
                return -1;
            default: // Unexpected error
                UI::print_error("Unexpected error in accept: " + std::string(strerror(errno)));
                receive_signal = false;
                return -1;
        }
    }

    UI::print_client_connected(inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    return client_fd;
}

void Server::close_server() {
    if (listen_fd >= 0)
        close(listen_fd);
    pthread_mutex_destroy(&users_mutex);
    pthread_mutex_destroy(&conn_fds_mutex);
}

void Server::ERR_EXIT(const char *msg) {
    std::perror(msg);
    close_server();
    exit(EXIT_FAILURE);
}

/* ===================================
   ClientConnection Implementation
   =================================== */

ClientConnection::ClientConnection(int client_fd) : fd(client_fd) {
    /* Get client IP address using getpeername */
    sockaddr_in peer_addr{};
    socklen_t addr_len = sizeof(peer_addr);
    if (getpeername(fd, (sockaddr*)&peer_addr, &addr_len) == 0)
        ip = inet_ntoa(peer_addr.sin_addr);
    
    pthread_mutex_lock(&conn_fds_mutex);
    conn_fds.push_back(fd);
    pthread_mutex_unlock(&conn_fds_mutex);
}

ClientConnection::~ClientConnection() {
    disconnect();
}

void ClientConnection::handle_command(const std::string& command) {
    std::istringstream iss(command);
    std::string command_type;
    iss >> command_type;
    
    std::string response = "";
    pthread_mutex_lock(&users_mutex);
    switch (std::stoi(command_type)) {
        case REGISTER: {
            std::string name, password;
            iss >> name >> password;
            if (!logged_in_name.empty())
                response = std::to_string(ERROR) + " " + std::to_string(MUST_LOGOUT_FIRST);
            else if (users.find(name) != users.end())
                response = std::to_string(ERROR) + " " + std::to_string(USER_EXISTS);
            else {
                users[name].password = password;
                response = std::to_string(SUCCESS);
            }
            break;
        }
        case LOGIN: {
            std::string name, password; 
            unsigned short port;
            iss >> name >> password >> port;
            if (!logged_in_name.empty())
                response = std::to_string(ERROR) + " " + std::to_string(MUST_LOGOUT_FIRST);
            else if (users.find(name) == users.end())
                response = std::to_string(ERROR) + " " + std::to_string(USER_NOT_FOUND);
            else if (users[name].password != password)
                response = std::to_string(ERROR) + " " + std::to_string(WRONG_PASSWORD);
            else if (users[name].online)
                response = std::to_string(ERROR) + " " + std::to_string(ALREADY_ONLINE);
            else {
                users[name].online = true;
                users[name].ip = ip;
                users[name].port = port;
                logged_in_name = name;
                response = std::to_string(SUCCESS);
            }
            break;
        }
        case LOGOUT: {
            std::string name;
            iss >> name;
            if (users.find(name) == users.end())
                response = std::to_string(ERROR) + " " + std::to_string(USER_NOT_FOUND);
            else if (!users[name].online)
                response = std::to_string(ERROR) + " " + std::to_string(NOT_ONLINE);
            else {
                users[name].online = false;
                users[name].ip.clear();
                users[name].port = 0;
                logged_in_name.clear();
                response = std::to_string(SUCCESS);
            }
            break;
        }
        case LIST: {
            if (logged_in_name.empty()) {
                response = std::to_string(ERROR) + " " + std::to_string(MUST_LOGIN_FIRST);
                break;
            }
            response = std::to_string(SUCCESS);
            for (const auto& pair : users) {
                if (pair.second.online)
                    response += " " + pair.first;
            }
            break;
        }
        case GET_ADDR: {
            if (logged_in_name.empty()) {
                response = std::to_string(ERROR) + " " + std::to_string(MUST_LOGIN_FIRST);
                break;
            }
            std::string target_name;
            iss >> target_name;
            if (users.find(target_name) == users.end())
                response = std::to_string(ERROR) + " " + std::to_string(USER_NOT_FOUND);
            else if (!users[target_name].online)
                response = std::to_string(ERROR) + " " + std::to_string(NOT_ONLINE);
            else
                response = std::to_string(SUCCESS) + " " + users[target_name].ip + " " + std::to_string(users[target_name].port);
            break;
        }
        default:
            response = std::to_string(ERROR) + " " + std::to_string(UNKNOWN_COMMAND);
    }
    pthread_mutex_unlock(&users_mutex);
    send_line(response);
}

void ClientConnection::send_line(const std::string& s) {
    std::string line = s + "\n";
    ssize_t total_sent = 0;
    ssize_t len = line.length();
    while (total_sent < len) {
        ssize_t sent = send(fd, line.c_str() + total_sent, len - total_sent, 0);
         if (sent < 0) {
            switch (errno) {
                case EINTR: // Interrupted by signal, retry
                    continue;
                case EAGAIN: // Send buffer full (non-blocking)
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000); // Wait for 1ms
                    continue;
                default:
                    ERR_EXIT("send");
            }
        }
        total_sent += sent;
    }
}

bool ClientConnection::recv_line(std::string& out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) {
            switch (errno) {
                case EINTR: // Interrupted by signal, retry
                    continue;
                case EAGAIN: // No data available (non-blocking)
                #if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
                #endif
                    usleep(1000); // Wait for 1ms
                    continue;
                default:
                    ERR_EXIT("recv");
            }
        }
        else if (n == 0)
            return false;

        if (c == '\n')
            return true;
        out += c;
    }
}

void ClientConnection::disconnect() {
    pthread_mutex_lock(&conn_fds_mutex);
    conn_fds.erase(std::remove(conn_fds.begin(), conn_fds.end(), fd), conn_fds.end());
    pthread_mutex_unlock(&conn_fds_mutex);

    if (!logged_in_name.empty()) {
        pthread_mutex_lock(&users_mutex);
        if (users.find(logged_in_name) != users.end()) {
            users[logged_in_name].online = false;
            users[logged_in_name].ip.clear();
            users[logged_in_name].port = 0;
        }
        pthread_mutex_unlock(&users_mutex);
    }
    close(fd);
}

void ClientConnection::ERR_EXIT(const char *msg) {
    std::perror(msg);
    disconnect();
    pthread_exit(nullptr);
}