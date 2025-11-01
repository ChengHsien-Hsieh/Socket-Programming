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

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

using namespace std;

struct User {
    string password;
    int port = -1;
    bool online = false;
};

unordered_map<string, User> users;
pthread_mutex_t users_mtx = PTHREAD_MUTEX_INITIALIZER;

static void send_line(int fd, const string &s) {
    string line = s + "\n";
    // TODO: Use send() to send 'line'
}

static bool recv_line(int fd, string &out) {
    out.clear();
    // TODO: implement recv() loop until '\n'
    return true;
}

void* handle_client(void* arg) {
    int fd = *(int*)arg;
    delete (int*)arg; 

    string line;
    while (recv_line(fd, line)) {
        istringstream iss(line);
        string cmd; iss >> cmd;

        if (cmd == "REGISTER") {
            string id, pw; iss >> id >> pw;
            pthread_mutex_lock(&users_mtx);
            // TODO: implement REGISTER logic
            pthread_mutex_unlock(&users_mtx);
            // send_line(fd, response);
        } 
        else if (cmd == "LOGIN") {
            string id, pw; int port; iss >> id >> pw >> port;
            pthread_mutex_lock(&users_mtx);
            // TODO: implement LOGIN logic
            pthread_mutex_unlock(&users_mtx);
            // send_line(fd, response);
        } 
        else if (cmd == "LOGOUT") {
            string id; iss >> id;
            pthread_mutex_lock(&users_mtx);
            // TODO: implement LOGOUT logic
            pthread_mutex_unlock(&users_mtx);
            // send_line(fd, response);
        } 
        else if (cmd == "LIST") {
            pthread_mutex_lock(&users_mtx);
            // TODO: implement LIST logic
            pthread_mutex_unlock(&users_mtx);
            // send_line(fd, response);
        } 
        else {
            send_line(fd, "ERROR UnknownCmd");
        }
    }

    close(fd);
    pthread_exit(nullptr);
}

int main(int argc, char **argv) {
    int port = (argc >= 2) ? stoi(argv[1]) : 8888;

    int listenfd;
    sockaddr_in addr{};
    /*
    TODO:
    1. Create a TCP socket 
    2. Bind the socket to the given port
    3. Start listening for connections
    */

    cout << "Server listening on 127.0.0.1:" << port << endl;

    while (true) {
        int cfd;
        // TODO: accept connection using listenfd
        // cfd = accept(listenfd, ...) 

        pthread_t tid;
        int *arg = new int(cfd);
        pthread_create(&tid, nullptr, handle_client, arg);
        pthread_detach(tid);
    }
}