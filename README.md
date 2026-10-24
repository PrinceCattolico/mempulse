# mempulse

Windows x64 process memory mapper, private/unbacked `PAGE_EXECUTE_READWRITE` anomaly detector, and live AoB (Array-of-Bytes) wildcard pattern scanner.

## Build

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Usage

```powershell
# List base addresses and modules for target process
.\build\Release\mempulse.exe notepad.exe

# Scan for RWX memory anomalies (unbacked shellcode/injected pages)
.\build\Release\mempulse.exe notepad.exe --rwx

# Scan live process memory for IDA-style wildcard byte patterns
.\build\Release\mempulse.exe notepad.exe --sig "48 8B 05 ? ? ? ? 48 85 C0"
```
