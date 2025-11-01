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

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

static void send_line(int fd, const string &s) {
    string line = s + "\n";
    // TODO: Use send() to send 'line'
}

static bool recv_line(int fd, string &out) {
    out.clear();
    // TODO: implement recv() loop until '\n'
    return true;
}

int main(int argc, char **argv) {
    string server_ip = (argc>=2)? argv[1] : "127.0.0.1";
    int server_port = (argc>=3)? stoi(argv[2]) : 8888;

    int sfd;
    sockaddr_in srv{};
    // TODO: Create socket and connect to server using server_ip and server_port
    if (connect(sfd, (sockaddr*)&srv, sizeof(srv)) < 0) {
        cerr << "連線伺服器失敗" << endl;
        return 1;
    }

    string my_id;
    cout << "Connected to server.\n"
         << "指令: register <id> <pw> | login <id> <pw> <port> | logout | list | quit\n";

    while (true) {
        cout << "cmd> ";
        string line;
        if (!getline(cin, line)) break;

        istringstream iss(line);
        string cmd;
        iss >> cmd;

        if (cmd == "register") {
            string id, pw;
            // TODO: Check if both id and pw are provided
            iss >> id >> pw;
            send_line(sfd, "REGISTER " + id + " " + pw);
            string resp;
            if (recv_line(sfd, resp)) cout << resp << endl;

        } else if (cmd == "login") {
            string id, pw;
            int port;
            // TODO: Check if id, pw, and port are provided correctly
            // TODO: Verify if port is valid
            iss >> id >> pw >> port;
            my_id = id;
            send_line(sfd, "LOGIN " + id + " " + pw + " " + to_string(port));
            string resp;
            if (recv_line(sfd, resp)) cout << resp << endl;

        } else if (cmd == "logout") {
            // TODO: Verify if the user has already logged in
            send_line(sfd, "LOGOUT " + my_id);
            string resp;
            if (recv_line(sfd, resp)) cout << resp << endl;

        } else if (cmd == "list") {
            send_line(sfd, "LIST");
            string resp;
            if (recv_line(sfd, resp)) cout << resp << endl;

        } else if (cmd == "quit") {
            cout << "Bye!\n";
            break;

        } else if (!cmd.empty()) {
            cout << "Unknown command\n";
        }
    }

    close(sfd);
    return 0;
}

