#include "sandbox.h"

#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

Sandbox::Sandbox(const std::string& sample) : samplePath(sample) {}

void Sandbox::executeInSandbox() {
#ifdef _WIN32
    // Create suspended process
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    if (!CreateProcessA(
            nullptr,
            const_cast<char*>(samplePath.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        std::cerr << "Sandbox: CreateProcess failed for " << samplePath << std::endl;
        return;
    }

    // Inject DLL or hooks
    // ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // Monitor with job object, limits
#else
    std::cout << "Sandbox execution is not implemented on Linux; skipping sample launch for "
              << samplePath << std::endl;
#endif
}
