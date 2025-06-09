#pragma once
#include <vector>
#include <string>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdio> // For std::snprintf

// Global logging variables (declarations)
extern std::vector<std::string> g_logMessages;
extern std::mutex g_logMutex;

#ifdef _DEBUG

// Function to add a pre-formatted message to the log
inline void AddLogEntry(const std::string& entry) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logMessages.push_back(entry);
    // Optional: Limit log size
    // if (g_logMessages.size() > 500) {
    //     g_logMessages.erase(g_logMessages.begin(), g_logMessages.begin() + 100); // Example: trim
    // }
}

// Function to format and log a message
inline void LogMessage(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    time_t in_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm buf_tm;
#ifdef _WIN32
    localtime_s(&buf_tm, &in_time_t); // Windows specific
#else
    localtime_r(&in_time_t, &buf_tm); // POSIX specific
#endif
    std::stringstream ss;
    ss << std::put_time(&buf_tm, "%Y-%m-%d %H:%M:%S");
    ss << ": " << message;
    AddLogEntry(ss.str());
}

// Variadic logging function for printf-style logging
template<typename ... Args>
inline void LogMessageF(const char* format, Args ... args) {
    int size_s = std::snprintf(nullptr, 0, format, args ...);
    if (size_s <= 0) { return; }
    auto size = static_cast<size_t>(size_s);
    std::vector<char> buf(size + 1);
    std::snprintf(buf.data(), size + 1, format, args ...);
    LogMessage(std::string(buf.data(), buf.data() + size));
}

#else // Release configuration (_DEBUG is not defined)

// Define empty inline functions to compile out logging calls
inline void AddLogEntry(const std::string&) { /* Do nothing */ }
inline void LogMessage(const std::string&) { /* Do nothing */ }
template<typename ... Args>
inline void LogMessageF(const char*, Args ...) { /* Do nothing */ }

#endif // _DEBUG
