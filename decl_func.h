#pragma once
#include <windows.h>
#include <windns.h>

typedef HMODULE(WINAPI* fnGetModuleHandleA)(
    LPCSTR lpModuleName
    );

typedef HMODULE(WINAPI* fnLoadLibraryA)(
    LPCSTR lpLibFileName
);

typedef FARPROC(WINAPI* fnGetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef PVOID(WINAPI* fnVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

typedef BOOL(WINAPI* fnFreeLibrary)(
    HMODULE hLibModule
    );

typedef PVOID(WINAPI* fnCreateThread)(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
    );

typedef PVOID(WINAPI* fnWaitForSingleObject)(
    HANDLE hHandle,
    DWORD  dwMilliseconds
    );

typedef VOID(WINAPI* fnSleep)(
    DWORD dwMilliseconds
    );

typedef BOOL(WINAPI* fnUnmapViewOfFile)(
    LPCVOID lpBaseAddress
    );

typedef DNS_STATUS(WINAPI* fnDnsQuery_W)(
    _In_                PCWSTR          pszName,
    _In_                WORD            wType,
    _In_                DWORD           Options,
    _Inout_opt_         PVOID           pExtra,
    _Outptr_result_maybenull_     PDNS_RECORD* ppQueryResults,
    _Outptr_opt_result_maybenull_ PVOID* pReserved
);