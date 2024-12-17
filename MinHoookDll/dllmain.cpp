#include "pch.h"
#include <windows.h>
#include "MinHook.h"
#include <iostream>
#include "fileHandler.h"

FileHandler logger;
std::string LOG_FILE_PATH = ".\\log.txt";

std::string convertLPCWSTRToString(LPCWSTR wideString) {
    std::string narrowString;
    while (*wideString) {
        narrowString += static_cast<char>(*wideString); // Narrow each wide character
        ++wideString;
    }
    return narrowString;
}

// Typedef for the original CreateFileW function
typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );

// Original CreateFileW pointer
CreateFileW_t fpCreateFileW = nullptr;

// Our hooked function
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // Check if the target file is ntdll.dll or kernel32.dll
    if (lpFileName != nullptr)
    {
        if (wcsstr(lpFileName, L"ntdll.dll") || wcsstr(lpFileName, L"kernel32.dll"))
        {
            logger.log(LOG_FILE_PATH, "Suspicious File Access Detected!");
            logger.log(LOG_FILE_PATH, "attempt to use CreateFileW on " + convertLPCWSTRToString(lpFileName));
            // Optionally, block this behavior
            return INVALID_HANDLE_VALUE;
        }
    }

    // Call the original CreateFileW function
    return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// Function to set up hooks
bool SetupHooks()
{
    // Initialize MinHook
    if (MH_Initialize() != MH_OK)
    {
        return false;
    }

    // Create a hook for CreateFileW
    if (MH_CreateHook(&CreateFileW, &HookedCreateFileW, reinterpret_cast<LPVOID*>(&fpCreateFileW)) != MH_OK)
    {
        return false;
    }

    // Enable the hook
    if (MH_EnableHook(&CreateFileW) != MH_OK)
    {
        return false;
    }

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        // Setup hooks directly in DllMain
        if (!SetupHooks())
        {
            MessageBoxW(nullptr, L"Failed to set up hooks!", L"Error", MB_ICONERROR);
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        // Cleanup hooks
        MH_DisableHook(&CreateFileW);
        MH_Uninitialize();
    }
    return TRUE;
}
