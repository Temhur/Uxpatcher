#include <Windows.h>
#include <DbgHelp.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>

#pragma comment(lib, "Dbghelp.lib")

// Leer todo el archivo a un vector
std::vector<uint8_t> read_all(const wchar_t* path) {
    std::ifstream is(path, std::ios::binary);
    if (!is) return {};
    is.seekg(0, std::ios::end);
    std::vector<uint8_t> data((size_t)is.tellg());
    is.seekg(0, std::ios::beg);
    is.read(reinterpret_cast<char*>(data.data()), data.size());
    return data;
}

// Guardar buffer a archivo
bool write_all(const wchar_t* path, const void* data, size_t size) {
    std::ofstream os(path, std::ios::binary);
    if (!os) return false;
    os.write((const char*)data, size);
    return os.good();
}

// RVA a FileOffset
uint32_t rva2fo(const uint8_t* image, uint32_t rva) {
    auto idh = (PIMAGE_DOS_HEADER)image;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto inh = (PIMAGE_NT_HEADERS)(image + idh->e_lfanew);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto sections = IMAGE_FIRST_SECTION(inh);
    for (int i = 0; i < inh->FileHeader.NumberOfSections; ++i) {
        auto& sec = sections[i];
        if (sec.PointerToRawData && sec.VirtualAddress <= rva && rva < sec.VirtualAddress + sec.SizeOfRawData)
            return rva - sec.VirtualAddress + sec.PointerToRawData;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Uso: uxptch.exe <DLL origen> <DLL salida>\n";
        return 1;
    }

    wchar_t dll_path[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, dll_path, MAX_PATH);

    HMODULE lib = LoadLibraryExW(dll_path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!lib) {
        std::wcerr << L"LoadLibraryExW fallo: " << GetLastError() << "\n";
        return 1;
    }

    wchar_t full_path[MAX_PATH];
    if (!GetModuleFileNameW(lib, full_path, MAX_PATH)) {
        std::wcerr << L"GetModuleFileNameW fallo: " << GetLastError() << "\n";
        return 1;
    }

    if (!SymInitializeW(GetCurrentProcess(), nullptr, FALSE)) {
        std::wcerr << L"SymInitializeW fallo: " << GetLastError() << "\n";
        return 1;
    }

    DWORD64 base = SymLoadModuleExW(GetCurrentProcess(), nullptr, full_path, nullptr, (DWORD64)lib, 0, nullptr, 0);
    if (!base) {
        std::wcerr << L"SymLoadModuleExW fallo: " << GetLastError() << "\n";
        return 1;
    }

    std::unordered_set<uint32_t> patch_rvas;

    SymEnumSymbolsW(GetCurrentProcess(), base, nullptr,
        [](PSYMBOL_INFOW sym, ULONG, PVOID ctx) -> BOOL {
            if (wcscmp(sym->Name, L"CThemeSignature::Verify") == 0) {
                ((std::unordered_set<uint32_t>*)ctx)->insert((uint32_t)(sym->Address - sym->ModBase));
            }
            return TRUE;
        }, &patch_rvas);

    if (patch_rvas.empty()) {
        std::wcerr << L"No se encontro CThemeSignature::Verify\n";
        return 1;
    }

    auto file = read_all(full_path);
    if (file.empty()) {
        std::wcerr << L"No se pudo leer el archivo\n";
        return 1;
    }

    // Patch x64
    uint8_t patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax ; ret

    for (auto rva : patch_rvas) {
        uint32_t fo = rva2fo(file.data(), rva);
        if (!fo) continue;
        memcpy(file.data() + fo, patch, sizeof(patch));
        std::wcout << L"Patched RVA " << std::hex << rva << L" at file offset " << fo << L"\n";
    }

    wchar_t out_path[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, out_path, MAX_PATH);

    if (!write_all(out_path, file.data(), file.size())) {
        std::wcerr << L"No se pudo escribir archivo de salida\n";
        return 1;
    }

    std::wcout << L"Archivo parcheado guardado en: " << out_path << L"\n";
    return 0;
}
