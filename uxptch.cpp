#include <Windows.h>
#include <DbgHelp.h>

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include <cstdint>
#include <filesystem>

#pragma comment(lib, "Dbghelp.lib")

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
    // compute NT headers base (cast away const for IMAGE_FIRST_SECTION macro)
    auto inh = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<uint8_t*>(image) + idh->e_lfanew);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto sections = IMAGE_FIRST_SECTION(inh);
    for (int i = 0; i < inh->FileHeader.NumberOfSections; ++i) {
        auto& sec = sections[i];
        uint32_t secVA = sec.VirtualAddress;
        uint32_t secSize = sec.SizeOfRawData ? sec.SizeOfRawData : sec.Misc.VirtualSize;
        if (sec.PointerToRawData && secVA <= rva && rva < secVA + secSize)
            return rva - secVA + sec.PointerToRawData;
    }
    return 0;
}

static BOOL CALLBACK EnumSymCallback(PSYMBOL_INFOW sym, ULONG /*symSize*/, PVOID ctx) {
    if (!sym || !sym->Name || !ctx) return TRUE;
    auto set = reinterpret_cast<std::unordered_set<uint32_t>*>(ctx);
    if (wcscmp(sym->Name, L"CThemeSignature::Verify") == 0) {
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
    const wchar_t* out_path = argv[2];

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

    // ensure undecorated names are available
    DWORD opts = SymGetOptions();
    opts |= SYMOPT_UNDNAME;
    SymSetOptions(opts);

    if (!SymInitializeW(GetCurrentProcess(), nullptr, FALSE)) {
        std::wcerr << L"SymInitializeW failed: " << GetLastError() << L"\n";
        FreeLibrary(lib);
        return 1;
    }

    // load module for symbol handling
    DWORD64 load_base = SymLoadModuleExW(GetCurrentProcess(), nullptr, fullpath, nullptr, reinterpret_cast<DWORD64>(lib), 0, nullptr, 0);
    if (load_base == 0) {
        std::wcerr << L"SymLoadModuleExW failed: " << GetLastError() << L"\n";
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    std::unordered_set<uint32_t> patch_rvas;
    // Use SymEnumSymbolsExW similarly to the provided reference
    if (!SymEnumSymbolsExW(GetCurrentProcess(), reinterpret_cast<DWORD64>(lib), nullptr, EnumSymCallback, &patch_rvas, SYMENUM_OPTIONS_DEFAULT)) {
        std::wcerr << L"SymEnumSymbolsExW failed: " << GetLastError() << L"\n";
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

    bool wrote = false;
    for (auto rva : patch_rvas) {
        uint32_t fo = rva2fo(file.data(), rva);
        std::wcout << L"found at rva " << std::hex << rva << L" file offset " << fo << std::dec << L"\n";
        if (fo == 0) continue;
        if (static_cast<size_t>(fo) + sizeof(patch) > file.size()) continue;
        if (0 != memcmp(file.data() + fo, patch, sizeof(patch))) {
            memcpy(file.data() + fo, patch, sizeof(patch));
            wrote = true;
        }
    }

    if (!wrote) {
        std::wcout << L"file already patched or nothing changed\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 0;
    }

    if (!write_all(out_path, file.data(), file.size())) {
        std::wcerr << L"write_all failed\n";
        SymUnloadModule64(GetCurrentProcess(), load_base);
        SymCleanup(GetCurrentProcess());
        FreeLibrary(lib);
        return 1;
    }

    std::wcout << L"Patched file written to: " << out_path << L"\n";

    SymUnloadModule64(GetCurrentProcess(), load_base);
    SymCleanup(GetCurrentProcess());
    FreeLibrary(lib);
    return 0;
}
