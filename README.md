# Socket Programming - Client-Server Application

A multi-threaded client-server application implemented in C++ using POSIX sockets and pthread. This project demonstrates user authentication, session management, and P2P connection preparation.

## Features

### Server
- ✅ Multi-threaded architecture using **thread pool** (10 worker threads)
- ✅ User registration and authentication system
- ✅ Session management (login/logout)
- ✅ Online user listing with P2P port information
- ✅ Graceful shutdown with signal handling (SIGINT/SIGTERM)
- ✅ Thread-safe operations with mutex protection
- ✅ RAII-based resource management

### Client
- ✅ Interactive command-line interface
- ✅ User registration and login
- ✅ P2P listening socket management
- ✅ Port availability validation
- ✅ Automatic resource cleanup
- ✅ Connection state synchronization with server

## System Requirements

- **OS**: Linux, macOS, or other UNIX-like systems
- **Compiler**: g++ with C++17 support
- **Libraries**: pthread (POSIX threads)

## Project Structure

```
socket_programming/
├── server.cpp          # Server implementation
├── server.hpp          # Server header
├── client.cpp          # Client implementation
├── client.hpp          # Client header
├── thread_pool.cpp     # Thread pool implementation
├── thread_pool.hpp     # Thread pool header
├── Makefile           # Build configuration
└── README.md          # This file
```

## Build Instructions

### Compile Everything
```bash
make
```

### Compile Server Only
```bash
make server
```

### Compile Client Only
```bash
make client
```

### Clean Build Artifacts
```bash
make clean
```

### Rebuild from Scratch
```bash
make rebuild
```

## Usage

### Starting the Server

```bash
# Use default port (8888)
./server

# Specify custom port
./server 9000
```

**Server Output:**
```
Server initialized and listening on 127.0.0.1:8888
Thread pool initialized with 10 workers
```

### Starting the Client

```bash
# Connect to default server (127.0.0.1:8888)
./client

# Connect to custom server
./client 127.0.0.1 9000
```

## Commands

### Register a New User
```
> register <username> <password>
```
**Example:**
```
> register alice mypassword123
Register Success!
```

### Login
```
> login <username> <password> <port>
```
- `port`: Port number for P2P listening socket (1024-65535)

**Example:**
```
> login alice mypassword123 9001
P2P listening socket created on port 9001
Login Success!
```

**Port Validation:**
- Must be a valid number (no letters or special characters)
- Must be in range 1024-65535
- Must be available (not already in use)

### Logout
```
> logout
```
**Example:**
```
> logout
Logout Success!
Closing P2P listening socket on port 9001
```

### List Online Users
```
> list
```
**Example:**
```
> list
Online Users: alice 9001 bob 9002
```

### Quit
```
> quit
```

## Architecture

### Server Architecture

```
Main Thread
    ↓
Signal Handler (SIGINT/SIGTERM)
    ↓
Accept Loop → Thread Pool (10 Workers)
    ↓              ↓
  Client 1    Client 2 ... Client N
    ↓              ↓
ClientConnection (RAII)
    ↓
Command Handler
```

**Key Components:**
- **Server**: Manages listening socket and accepts connections
- **ThreadPool**: Maintains worker threads and task queue
- **ClientConnection**: Handles individual client sessions (RAII)
- **Signal Handler**: Ensures graceful shutdown

### Client Architecture

```
Main Thread
    ↓
ServerConnection (RAII)
    ↓
Command Loop
    ↓
├─ register
├─ login → Create P2P Listening Socket
├─ logout → Close P2P Listening Socket
├─ list
└─ quit
```

**Key Components:**
- **ServerConnection**: Manages connection to server (RAII)
- **P2P Listening Socket**: Created on login, closed on logout
- **Input Validation**: Ensures port numbers are valid and available

## Error Handling

### Server Errors
- `ERROR UserExists` - Username already registered
- `ERROR UserNotFound` - User does not exist
- `ERROR WrongPassword` - Incorrect password
- `ERROR AlreadyOnline` - User is already logged in
- `ERROR YouHaveToLogoutFirst` - Must logout before registering/logging in as another user
- `ERROR YouMustLoginFirst` - Must login before listing users
- `ERROR NotOnline` - User is not currently online
- `ERROR UnknownCommand` - Invalid command

### Client Errors
- `Error: Port must be a valid number` - Non-numeric port input
- `Error: Port must be between 1024 and 65535` - Port out of valid range
- `Error: Port X is not available` - Port already in use
- `Error: You must login first` - Logout attempted without login

## Threading Model

### Thread Pool Implementation
- **Fixed size**: 10 worker threads
- **Task queue**: FIFO queue with mutex protection
- **Condition variable**: Efficient worker wake-up
- **Graceful shutdown**: 
  1. Close pending connections in queue
  2. Wait for active workers to finish
  3. Join all threads

### Thread Safety
- **Global data structures** protected by mutexes:
  - `users` - User database (mutex: `users_mutex`)
  - `active_clients` - Active client FDs (mutex: `clients_mutex`)
- **Atomic flag**: `server_running` for shutdown coordination

## Signal Handling

### Signals Caught
- **SIGINT** (Ctrl+C): User interrupt
- **SIGTERM**: Termination signal

### Shutdown Process
1. Signal handler sets `server_running = false`
2. Main thread exits accept loop
3. Thread pool stops accepting new tasks
4. Pending connections are closed
5. Active workers finish current tasks
6. All threads join
7. Server exits cleanly

### Signal Mask Strategy
```cpp
// Block signals in main thread
pthread_sigmask(SIG_BLOCK, ...);

// Create worker threads (inherit blocked mask)
ThreadPool thread_pool(10);

// Register handler and unblock in main thread only
sigaction(SIGINT, ...);
pthread_sigmask(SIG_UNBLOCK, ...);
```
**Result**: Only main thread handles signals, workers are not interrupted.

## Design Patterns

### RAII (Resource Acquisition Is Initialization)
All socket resources are managed using RAII:

```cpp
class Server {
    ~Server() {
        if (listen_fd >= 0)
            close(listen_fd);
    }
};

class ClientConnection {
    ~ClientConnection() {
        // Automatic logout on disconnect
        if (!logged_in_name.empty()) {
            users[logged_in_name].online = false;
        }
        close(fd);
    }
};
```

**Benefits:**
- Automatic resource cleanup
- Exception-safe
- No memory/socket leaks

### Thread Pool Pattern
- Reuses worker threads for efficiency
- Avoids overhead of creating/destroying threads per request
- Bounded resource usage

## Testing

### Basic Flow Test
```bash
# Terminal 1: Start server
./server

# Terminal 2: Client 1
./client
> register alice 1234
> login alice 1234 9001
> list

# Terminal 3: Client 2
./client
> register bob 5678
> login bob 5678 9002
> list

# Both should see each other online
```

### Port Conflict Test
```bash
# Client 1
> login alice 1234 9001

# Client 2 (should fail)
> login bob 5678 9001
Error: Port 9001 is not available
```

### Graceful Shutdown Test
```bash
# With active clients connected
# Press Ctrl+C in server terminal
^C
Received SIGINT (Ctrl+C)
Closing 0 pending connections...
Server closed successfully.
```

## Known Limitations

1. **Localhost only**: Server listens on 127.0.0.1
2. **No encryption**: All communication is plaintext
3. **No persistence**: User data is lost on server restart
4. **Basic authentication**: Passwords are stored in memory without hashing
5. **No P2P implementation**: Client only creates listening socket, actual P2P communication is not implemented

## Future Enhancements

- [ ] Add SSL/TLS encryption
- [ ] Implement actual P2P messaging
- [ ] Add database persistence (SQLite)
- [ ] Add password hashing (bcrypt/argon2)
- [ ] Support multiple network interfaces
- [ ] Add connection timeout handling
- [ ] Implement reconnection logic
- [ ] Add logging system
- [ ] Add configuration file support
- [ ] Implement rate limiting

## Troubleshooting

### "Address already in use" Error
```bash
# Wait a few seconds for TIME_WAIT to clear, or
# Kill the existing process
ps aux | grep server
kill <PID>
```

### "Port not available" Error
```bash
# Check if port is in use
lsof -i :9001
# or
netstat -an | grep 9001
```

### Compilation Errors
```bash
# Ensure you have C++17 support
g++ --version  # Should be >= 7.0

# Make sure pthread is available
ldconfig -p | grep pthread
```

## License

This project is for educational purposes as part of a Computer Networks course.

## Author

ChengHsien-Hsieh

## Acknowledgments

- POSIX thread documentation
- Beej's Guide to Network Programming
- Computer Networks course materials
