#include <Windows.h>
#include <DbgHelp.h>
#include <Aclapi.h>

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include <cstdint>
#include <filesystem>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Advapi32.lib")

static std::vector<uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream is(path, std::ios::binary);
    if (!is) return {};
    is.seekg(0, std::ios::end);
    std::vector<uint8_t> data((size_t)is.tellg());
    is.seekg(0, std::ios::beg);
    is.read(reinterpret_cast<char*>(data.data()), data.size());
    return data;
}

static bool write_all(const std::filesystem::path& path, const void* data, size_t size) {
    std::ofstream os(path, std::ios::binary);
    if (!os) return false;
    os.write(reinterpret_cast<const char*>(data), size);
    return os.good();
}

static uint32_t rva2fo(const uint8_t* image, uint32_t rva) {
    if (!image) return 0;
    auto idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const uint8_t* ntBase = image + idh->e_lfanew;
    auto inh = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntBase);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto sections = IMAGE_FIRST_SECTION(inh);
    for (int i = 0; i < inh->FileHeader.NumberOfSections; ++i) {
        const auto& sec = sections[i];
        uint32_t secVA = sec.VirtualAddress;
        uint32_t secSize = sec.SizeOfRawData ? sec.SizeOfRawData : sec.Misc.VirtualSize;
        if (sec.PointerToRawData && secVA <= rva && rva < secVA + secSize) {
            return rva - secVA + sec.PointerToRawData;
        }
    }
    return 0;
}

static bool TakeOwnership(const wchar_t* path) {
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp{};
        LUID luid;
        // Use wide-string privilege name
        if (LookupPrivilegeValueW(nullptr, L"SeTakeOwnershipPrivilege", &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }

    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    PSID adminSid = sidBuf;
    DWORD sidSize = sizeof(sidBuf);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &sidSize)) {
        adminSid = nullptr;
    }

    DWORD res = SetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, adminSid, nullptr, nullptr, nullptr);

    return (res == ERROR_SUCCESS);
}

static BOOL CALLBACK EnumSymCallback(PSYMBOL_INFOW sym, ULONG /*symSize*/, PVOID ctx) {
    if (!sym || !sym->Name || !ctx) return TRUE;
    auto set = reinterpret_cast<std::unordered_set<uint32_t>*>(ctx);

    if (wcscmp(sym->Name, L"CThemeSignature::Verify") == 0 ||
        (wcsstr(sym->Name, L"CThemeSignature") && wcsstr(sym->Name, L"Verify"))) {
        uint64_t addr = sym->Address;
        uint64_t modBase = sym->ModBase;
        if (addr >= modBase) {
            set->insert(static_cast<uint32_t>(addr - modBase));
        }
    }
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcout << L"Uso: uxptch.exe <DLL origen> <DLL salida>\n";
        return 1;
    }

    const wchar_t* dll_path = argv[1];
    const wchar_t* out_path_arg = argv[2];

    std::wcout << L"Trying image " << dll_path << L"\n";

    HMODULE lib = LoadLibraryExW(dll_path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!lib) {
        std::wcerr << L"LoadLibraryExW failed: " << GetLastError() << L"\n";
        return 1;
    }

    wchar_t fullpath[MAX_PATH]{};
    if (!GetModuleFileNameW(lib, fullpath, (DWORD)std::size(fullpath))) {
        std::wcerr << L"GetModuleFileNameW failed: " << GetLastError() << L"\n";
        FreeLibrary(lib);
        return 1;
    }

    // Symbol options
    DWORD opts = SymGetOptions();
    opts |= SYMOPT_UNDNAME;
    opts |= SYMOPT_DEFERRED_LOADS;
    opts |= SYMOPT_LOAD_LINES;
    SymSetOptions(opts);

    // Optional symbol server path (comment out if not needed)
    SymSetSearchPathW(GetCurrentProcess(), L"SRV*C:\\symbols*https://msdl.microsoft.com/download/symbols");

    if (!SymInitializeW(GetCurrentProcess(), nullptr, FALSE)) {
        std::wcerr << L"SymInitializeW failed: " << GetLastError() << L"\n";
        FreeLibrary(lib);
        return 1;
    }

    DWORD64 load_base = SymLoadModuleExW(GetCurrentProcess(), nullptr, fullpath, nullptr, reinterpret_cast<DWORD64>(lib), 0, nullptr, 0);
    if (load_base == 0) {
        std::wcerr << L"SymLoadModuleExW failed: " << GetLastError() << L"\n";
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    std::unordered_set<uint32_t> patch_rvas;
    if (!SymEnumSymbolsW(GetCurrentProcess(), load_base, nullptr, EnumSymCallback, &patch_rvas)) {
        std::wcerr << L"SymEnumSymbolsW failed: " << GetLastError() << L"\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    if (patch_rvas.empty()) {
        std::wcerr << L"No se encontro CThemeSignature::Verify\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    std::filesystem::path file_path(fullpath);
    auto file = read_all(file_path);
    if (file.empty()) {
        std::wcerr << L"can't read file\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    // x64 patch only
    constexpr static uint8_t patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax ; ret

    unsigned patched = 0;
    for (auto rva : patch_rvas) {
        uint32_t fo = rva2fo(file.data(), rva);
        std::wcout << L"found at rva " << std::hex << rva << L" file offset " << fo << std::dec << L"\n";
        if (fo == 0) continue;
        if (static_cast<size_t>(fo) + sizeof(patch) > file.size()) {
            std::wcerr << L"Patch would go out of bounds, skipping\n";
            continue;
        }
        if (0 != memcmp(file.data() + fo, patch, sizeof(patch))) {
            memcpy(file.data() + fo, patch, sizeof(patch));
            ++patched;
        }
    }

    if (patched == 0) {
        std::wcout << L"file already patched!\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return static_cast<int>(patch_rvas.size());
    }

    std::filesystem::path patched_path = file_path;
    patched_path += L".patched";
    std::filesystem::path backup_path = file_path;
    backup_path += L".bak";

    if (!write_all(patched_path, file.data(), file.size())) {
        std::wcerr << L"write_all failed\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    if (!TakeOwnership(fullpath)) {
        std::wcerr << L"TakeOwnership failed: " << GetLastError() << L"\n";
    }

    if (!MoveFileW(fullpath, backup_path.c_str())) {
        std::wcerr << L"MoveFileW " << fullpath << L" -> " << backup_path.c_str() << L" failed: " << GetLastError() << L"\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    if (!MoveFileW(patched_path.c_str(), fullpath)) {
        std::wcerr << L"MoveFileW " << patched_path.c_str() << L" -> " << fullpath << L" failed: " << GetLastError() << L"\n";
        if (!MoveFileW(backup_path.c_str(), fullpath)) {
            std::wcerr << L"MoveFileW " << backup_path.c_str() << L" -> " << fullpath << L" failed: " << GetLastError() << L". This is pretty bad!\n";
        }
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    std::wcout << L"Patched file saved to: " << fullpath << L"\n";

    SymUnloadModule64(GetCurrentProcess(), load_base);
    SymCleanup(GetCurrentProcess());
    FreeLibrary(lib);

    return static_cast<int>(patch_rvas.size());
}
