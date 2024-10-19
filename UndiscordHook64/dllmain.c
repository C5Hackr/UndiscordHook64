#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include "detours.h"

LPVOID GetFunction(LPCSTR dll, LPCSTR function)
{
    HMODULE module = GetModuleHandleA(dll);
    return module ? (LPVOID)GetProcAddress(module, function) : NULL;
}

static VOID InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
    *originalFunction = GetFunction(dll, function);
    if (*originalFunction) DetourAttach(originalFunction, hookedFunction);
}

typedef NTSTATUS(__stdcall* typedef_LdrLoadDll)(PWSTR aSearchPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* BaseAddress);
static typedef_LdrLoadDll OriginalLdrLoadDll;

static NTSTATUS __stdcall HookedLdrLoadDll(PWSTR aSearchPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* BaseAddress)
{
    BOOL PreventDllLoad = FALSE;

    if (wcsstr(DllName->Buffer, L"DiscordHook64.dll") != 0)
    {

        PreventDllLoad = TRUE;
    }

    if (PreventDllLoad)
    {
        return STATUS_ACCESS_DENIED;
    }
    else
    {
        return OriginalLdrLoadDll(aSearchPath, DllCharacteristics, DllName, BaseAddress);
    }
}

VOID InitHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    InstallHook("ntdll.dll", "LdrLoadDll", (LPVOID*)&OriginalLdrLoadDll, HookedLdrLoadDll);
    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            InitHooks();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}