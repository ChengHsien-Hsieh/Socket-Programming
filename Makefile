# ==========================================
# Makefile for Socket Programming Project
# ==========================================

# 編譯器和編譯選項
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -pthread

# 目標檔案
SERVER = server
CLIENT = client

# 原始檔案
SERVER_SRC = server.cpp thread_pool.cpp
CLIENT_SRC = client.cpp

# 標頭檔案
SERVER_HDR = server.hpp thread_pool.hpp
CLIENT_HDR = client.hpp

# 預設目標：編譯所有程式
all: $(SERVER) $(CLIENT)

# 編譯 server
$(SERVER): $(SERVER_SRC) $(SERVER_HDR)
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER) $(LDFLAGS)
	@echo "✅ Server compiled successfully!"

# 編譯 client
$(CLIENT): $(CLIENT_SRC) $(CLIENT_HDR)
	$(CXX) $(CXXFLAGS) $(CLIENT_SRC) -o $(CLIENT)
	@echo "✅ Client compiled successfully!"

# 只編譯 server
build-server: $(SERVER)

# 只編譯 client
build-client: $(CLIENT)

# 清理編譯產生的檔案
clean:
	rm -f $(SERVER) $(CLIENT)
	@echo "🧹 Cleaned up executables"

# 執行 server (預設 port 8888)
run-server: $(SERVER)
	./$(SERVER)

# 執行 client (預設連到 localhost:8888)
run-client: $(CLIENT)
	./$(CLIENT)

# 重新編譯
rebuild: clean all

# 顯示幫助訊息
help:
	@echo "Available targets:"
	@echo "  make          - 編譯 server 和 client"
	@echo "  make server   - 只編譯 server"
	@echo "  make client   - 只編譯 client"
	@echo "  make clean    - 清除編譯檔案"
	@echo "  make rebuild  - 清除後重新編譯"
	@echo "  make run-server - 編譯並執行 server (port 8888)"
	@echo "  make run-client - 編譯並執行 client (localhost:8888)"
	@echo "  make help     - 顯示此幫助訊息"

# 宣告假目標（不是實際檔案）
.PHONY: all server client clean run-server run-client rebuild help
