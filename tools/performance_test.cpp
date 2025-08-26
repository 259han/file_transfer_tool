#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <string>
#include <sstream>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class SimpleClient {
public:
    SimpleClient(const std::string& host, int port) 
        : host_(host), port_(port), connected_(false) {}
    
    bool connect() {
        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0) {
            return false;
        }
        
        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port_);
        inet_pton(AF_INET, host_.c_str(), &server_addr.sin_addr);
        
        if (::connect(sock_, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sock_);
            return false;
        }
        
        connected_ = true;
        return true;
    }
    
    void disconnect() {
        if (connected_) {
            close(sock_);
            connected_ = false;
        }
    }
    
    bool send_data(const std::string& data) {
        if (!connected_) return false;
        
        ssize_t sent = send(sock_, data.c_str(), data.length(), 0);
        return sent == static_cast<ssize_t>(data.length());
    }
    
    bool recv_data(std::string& data, size_t max_size = 1024) {
        if (!connected_) return false;
        
        std::vector<char> buffer(max_size);
        ssize_t received = recv(sock_, buffer.data(), max_size - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            data = buffer.data();
            return true;
        }
        return false;
    }

private:
    std::string host_;
    int port_;
    int sock_;
    bool connected_;
};

class PerformanceTester {
public:
    PerformanceTester(const std::string& host, int port, int num_clients, int requests_per_client)
        : host_(host), port_(port), num_clients_(num_clients), 
          requests_per_client_(requests_per_client),
          total_requests_(0), successful_requests_(0), failed_requests_(0) {}
    
    void run_test() {
        std::cout << "Starting performance test..." << std::endl;
        std::cout << "Host: " << host_ << ":" << port_ << std::endl;
        std::cout << "Clients: " << num_clients_ << std::endl;
        std::cout << "Requests per client: " << requests_per_client_ << std::endl;
        std::cout << "Total requests: " << num_clients_ * requests_per_client_ << std::endl;
        std::cout << "===========================================" << std::endl;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 创建客户端线程
        std::vector<std::thread> threads;
        for (int i = 0; i < num_clients_; i++) {
            threads.emplace_back(&PerformanceTester::client_thread, this, i);
        }
        
        // 等待所有线程完成
        for (auto& thread : threads) {
            thread.join();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // 打印结果
        print_results(duration.count());
    }

private:
    void client_thread(int client_id) {
        SimpleClient client(host_, port_);
        
        // 尝试连接
        if (!client.connect()) {
            std::cout << "Client " << client_id << " failed to connect" << std::endl;
            failed_requests_ += requests_per_client_;
            return;
        }
        
        // 发送请求
        for (int i = 0; i < requests_per_client_; i++) {
            total_requests_++;
            
            std::stringstream ss;
            ss << "Hello from client " << client_id << " request " << i;
            std::string request = ss.str();
            
            if (client.send_data(request)) {
                std::string response;
                if (client.recv_data(response)) {
                    successful_requests_++;
                } else {
                    failed_requests_++;
                }
            } else {
                failed_requests_++;
            }
            
            // 小延迟避免过于激进
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        
        client.disconnect();
    }
    
    void print_results(long duration_ms) {
        std::cout << "\n===========================================" << std::endl;
        std::cout << "Performance Test Results:" << std::endl;
        std::cout << "===========================================" << std::endl;
        std::cout << "Total requests: " << total_requests_.load() << std::endl;
        std::cout << "Successful requests: " << successful_requests_.load() << std::endl;
        std::cout << "Failed requests: " << failed_requests_.load() << std::endl;
        std::cout << "Success rate: " << (100.0 * successful_requests_.load() / total_requests_.load()) << "%" << std::endl;
        std::cout << "Total time: " << duration_ms << " ms" << std::endl;
        
        if (duration_ms > 0) {
            double rps = 1000.0 * successful_requests_.load() / duration_ms;
            std::cout << "Requests per second: " << rps << std::endl;
        }
        
        std::cout << "===========================================" << std::endl;
    }

private:
    std::string host_;
    int port_;
    int num_clients_;
    int requests_per_client_;
    
    std::atomic<int> total_requests_;
    std::atomic<int> successful_requests_;
    std::atomic<int> failed_requests_;
};

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
#endif

    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <host> <port> [num_clients] [requests_per_client]" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    
    std::string host = argv[1];
    int port = std::stoi(argv[2]);
    int num_clients = argc > 3 ? std::stoi(argv[3]) : 10;
    int requests_per_client = argc > 4 ? std::stoi(argv[4]) : 100;
    
    PerformanceTester tester(host, port, num_clients, requests_per_client);
    tester.run_test();
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
