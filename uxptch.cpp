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

// Leer todo el archivo a un vector
std::vector<uint8_t> read_all(const std::filesystem::path& path) {
    std::ifstream is(path, std::ios::binary);
    if (!is) return {};
    is.seekg(0, std::ios::end);
    std::vector<uint8_t> data((size_t)is.tellg());
    is.seekg(0, std::ios::beg);
    is.read(reinterpret_cast<char*>(data.data()), data.size());
    return data;
}

// Guardar buffer a archivo
bool write_all(const std::filesystem::path& path, const void* data, size_t size) {
    std::ofstream os(path, std::ios::binary);
    if (!os) return false;
    os.write(reinterpret_cast<const char*>(data), size);
    return os.good();
}

// RVA a FileOffset
uint32_t rva2fo(const uint8_t* image, uint32_t rva) {
    if (!image) return 0;
    auto idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    // cast to non-const for NT headers/sections computation
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
    auto set = reinterpret_cast<std::unordered_set<uint32_t>*>(ctx);
    if (!sym || !set) return TRUE;
    if (wcscmp(sym->Name, L"CThemeSignature::Verify") == 0) {
        uint64_t addr = sym->Address;
        uint64_t modBase = sym->ModBase;
        if (addr >= modBase) {
            set->insert(static_cast<uint32_t>(addr - modBase));
        }
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Uso: uxptch.exe <DLL origen> <DLL salida>\n";
        return 1;
    }

    wchar_t dll_path_w[MAX_PATH]{};
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, dll_path_w, MAX_PATH);

    HMODULE lib = LoadLibraryExW(dll_path_w, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!lib) {
        std::wcerr << L"LoadLibraryExW fallo: " << GetLastError() << L"\n";
        return 1;
    }

    wchar_t full_path_w[MAX_PATH]{};
    if (!GetModuleFileNameW(lib, full_path_w, MAX_PATH)) {
        std::wcerr << L"GetModuleFileNameW fallo: " << GetLastError() << L"\n";
        return 1;
    }

    if (!SymInitializeW(GetCurrentProcess(), nullptr, FALSE)) {
        std::wcerr << L"SymInitializeW fallo: " << GetLastError() << L"\n";
        return 1;
    }

    DWORD64 base = SymLoadModuleExW(GetCurrentProcess(), nullptr, full_path_w, nullptr, reinterpret_cast<DWORD64>(lib), 0, nullptr, 0);
    if (!base) {
        std::wcerr << L"SymLoadModuleExW fallo: " << GetLastError() << L"\n";
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    std::unordered_set<uint32_t> patch_rvas;

    if (!SymEnumSymbolsW(GetCurrentProcess(), base, nullptr, EnumSymCallback, &patch_rvas)) {
        std::wcerr << L"SymEnumSymbolsW fallo: " << GetLastError() << L"\n";
        SymUnloadModule64(GetCurrentProcess(), base);
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    if (patch_rvas.empty()) {
        std::wcerr << L"No se encontro CThemeSignature::Verify\n";
        SymUnloadModule64(GetCurrentProcess(), base);
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    std::filesystem::path full_path(full_path_w);
    auto file = read_all(full_path);
    if (file.empty()) {
        std::wcerr << L"No se pudo leer el archivo\n";
        SymUnloadModule64(GetCurrentProcess(), base);
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    // Patch x64: xor eax,eax ; ret  -> 31 C0 C3
    uint8_t patch[] = { 0x31, 0xC0, 0xC3 };

    for (auto rva : patch_rvas) {
        uint32_t fo = rva2fo(file.data(), rva);
        if (!fo) {
            std::wcout << L"No se pudo convertir RVA " << std::hex << rva << L" a file offset\n";
            continue;
        }
        if (static_cast<size_t>(fo) + sizeof(patch) <= file.size()) {
            memcpy(file.data() + fo, patch, sizeof(patch));
            std::wcout << L"Patched RVA " << std::hex << rva << L" at file offset " << fo << L"\n";
        } else {
            std::wcout << L"Patch fuera de rango para RVA " << std::hex << rva << L"\n";
        }
    }

    std::filesystem::path out_path;
    {
        wchar_t out_path_w[MAX_PATH]{};
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, out_path_w, MAX_PATH);
        out_path = out_path_w;
    }

    if (!write_all(out_path, file.data(), file.size())) {
        std::wcerr << L"No se pudo escribir archivo de salida\n";
        SymUnloadModule64(GetCurrentProcess(), base);
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    std::wcout << L"Archivo parcheado guardado en: " << out_path.wstring() << L"\n";

    SymUnloadModule64(GetCurrentProcess(), base);
    SymCleanup(GetCurrentProcess());
    return 0;
}
