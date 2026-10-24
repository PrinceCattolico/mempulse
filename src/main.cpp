#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <sstream>

struct SigByte {
    uint8_t value;
    bool wildcard;
};

struct ModuleRegion {
    std::string name;
    uintptr_t base;
    size_t size;
};

static DWORD find_pid_by_name(const char* proc_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, proc_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static std::vector<ModuleRegion> list_modules(DWORD pid) {
    std::vector<ModuleRegion> mods;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return mods;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            mods.push_back(ModuleRegion{
                me.szModule,
                reinterpret_cast<uintptr_t>(me.modBaseAddr),
                static_cast<size_t>(me.modBaseSize)
            });
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return mods;
}

static std::vector<SigByte> parse_pattern(const std::string& pattern) {
    std::vector<SigByte> out;
    std::istringstream iss(pattern);
    std::string tok;
    while (iss >> tok) {
        if (tok == "?" || tok == "??") {
            out.push_back({0, true});
        } else {
            char* endp = nullptr;
            unsigned long v = std::strtoul(tok.c_str(), &endp, 16);
            if (endp == tok.c_str() || v > 0xFF) {
                return {};
            }
            out.push_back({static_cast<uint8_t>(v), false});
        }
    }
    return out;
}

static const char* prot_to_str(DWORD prot) {
    switch (prot & 0xFF) {
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_READ:      return "R-X";
        case PAGE_EXECUTE_WRITECOPY: return "RCX";
        case PAGE_READWRITE:         return "RW-";
        case PAGE_READONLY:          return "R--";
        default:                     return "---";
    }
}

static void scan_process(HANDLE hProc, const std::vector<SigByte>& sig, bool rwx_only) {
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    std::vector<uint8_t> buffer;

    printf("%-18s %-12s %-6s %-10s\n", "BASE", "SIZE", "PROT", "TYPE");
    while (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t reg_size = mbi.RegionSize;

        bool committed = (mbi.State == MEM_COMMIT);
        bool guarded = (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS);
        bool is_rwx = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;

        if (committed && !guarded) {
            if (!rwx_only || is_rwx) {
                const char* mtype = (mbi.Type == MEM_IMAGE) ? "IMAGE" :
                                    (mbi.Type == MEM_MAPPED) ? "MAPPED" : "PRIVATE";
                if (rwx_only) {
                    printf("0x%016llX 0x%010llX %-6s %-10s [ANOMALY]\n",
                           static_cast<unsigned long long>(base),
                           static_cast<unsigned long long>(reg_size),
                           prot_to_str(mbi.Protect), mtype);
                }
            }

            if (!sig.empty() && reg_size >= sig.size() && reg_size <= (64ULL << 20)) {
                buffer.resize(reg_size);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base), buffer.data(), reg_size, &bytes_read) &&
                    bytes_read >= sig.size()) {
                    size_t limit = bytes_read - sig.size() + 1;
                    for (size_t i = 0; i < limit; ++i) {
                        bool match = true;
                        for (size_t j = 0; j < sig.size(); ++j) {
                            if (!sig[j].wildcard && buffer[i + j] != sig[j].value) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            printf("[SIG HIT] 0x%016llX (+0x%llX in region 0x%016llX %s)\n",
                                   static_cast<unsigned long long>(base + i),
                                   static_cast<unsigned long long>(i),
                                   static_cast<unsigned long long>(base),
                                   prot_to_str(mbi.Protect));
                        }
                    }
                }
            }
        }

        uintptr_t next = base + reg_size;
        if (next <= addr) break;
        addr = next;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n  %s <process_name_or_pid> [--rwx] [--sig \"48 8B 05 ? ? ? ?\"]\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;
    char* endp = nullptr;
    unsigned long parsed_pid = std::strtoul(argv[1], &endp, 10);
    if (endp && *endp == '\0' && parsed_pid > 0) {
        pid = static_cast<DWORD>(parsed_pid);
    } else {
        pid = find_pid_by_name(argv[1]);
    }

    if (pid == 0) {
        fprintf(stderr, "Target process not found: %s\n", argv[1]);
        return 1;
    }

    bool rwx_only = false;
    std::vector<SigByte> sig;

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--rwx") == 0) {
            rwx_only = true;
        } else if (std::strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
            sig = parse_pattern(argv[++i]);
            if (sig.empty()) {
                fprintf(stderr, "Invalid signature format.\n");
                return 1;
            }
        }
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "OpenProcess failed for PID %lu (err=%lu)\n", pid, GetLastError());
        return 1;
    }

    printf("Target PID : %lu\n", pid);
    auto mods = list_modules(pid);
    printf("Modules    : %zu loaded\n", mods.size());
    for (size_t i = 0; i < mods.size() && i < 12; ++i) {
        printf("  [0x%016llX - 0x%016llX] %s\n",
               static_cast<unsigned long long>(mods[i].base),
               static_cast<unsigned long long>(mods[i].base + mods[i].size),
               mods[i].name.c_str());
    }

    if (rwx_only || !sig.empty()) {
        printf("\n");
        scan_process(hProc, sig, rwx_only);
    }

    CloseHandle(hProc);
    return 0;
}
