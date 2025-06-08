#include "Logging.h" // Or your common header like pch.h if it includes Logging.h

// Global logging variables (definitions)
std::vector<std::string> g_logMessages;
std::mutex g_logMutex;
