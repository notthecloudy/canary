use canary_sdb::types::SdbFunctionType;
use canary_sdb::{RecoveryOrigin, SdbEntry, SdbParam, SemanticDatabase};
use indexmap::IndexMap;
use std::sync::OnceLock;

struct TypeLibEntry {
    return_ty: &'static str,
    params: &'static [(&'static str, &'static str)],
    calling_conv: &'static str,
}

fn get_type_lib() -> &'static IndexMap<&'static str, TypeLibEntry> {
    static TYPE_LIB: OnceLock<IndexMap<&'static str, TypeLibEntry>> = OnceLock::new();
    TYPE_LIB.get_or_init(|| {
        let mut lib = IndexMap::new();

        // Win32 APIs
        lib.insert(
            "CreateFileW",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[
                    ("lpFileName", "LPCWSTR"),
                    ("dwDesiredAccess", "DWORD"),
                    ("dwShareMode", "DWORD"),
                    ("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
                    ("dwCreationDisposition", "DWORD"),
                    ("dwFlagsAndAttributes", "DWORD"),
                    ("hTemplateFile", "HANDLE"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "CreateFileA",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[
                    ("lpFileName", "LPCSTR"),
                    ("dwDesiredAccess", "DWORD"),
                    ("dwShareMode", "DWORD"),
                    ("lpSecurityAttributes", "LPSECURITY_ATTRIBUTES"),
                    ("dwCreationDisposition", "DWORD"),
                    ("dwFlagsAndAttributes", "DWORD"),
                    ("hTemplateFile", "HANDLE"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "ReadFile",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[
                    ("hFile", "HANDLE"),
                    ("lpBuffer", "LPVOID"),
                    ("nNumberOfBytesToRead", "DWORD"),
                    ("lpNumberOfBytesRead", "LPDWORD"),
                    ("lpOverlapped", "LPOVERLAPPED"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "WriteFile",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[
                    ("hFile", "HANDLE"),
                    ("lpBuffer", "LPCVOID"),
                    ("nNumberOfBytesToWrite", "DWORD"),
                    ("lpNumberOfBytesWritten", "LPDWORD"),
                    ("lpOverlapped", "LPOVERLAPPED"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "CloseHandle",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[("hObject", "HANDLE")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "VirtualAlloc",
            TypeLibEntry {
                return_ty: "LPVOID",
                params: &[
                    ("lpAddress", "LPVOID"),
                    ("dwSize", "SIZE_T"),
                    ("flAllocationType", "DWORD"),
                    ("flProtect", "DWORD"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "VirtualFree",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[
                    ("lpAddress", "LPVOID"),
                    ("dwSize", "SIZE_T"),
                    ("dwFreeType", "DWORD"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "VirtualProtect",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[
                    ("lpAddress", "LPVOID"),
                    ("dwSize", "SIZE_T"),
                    ("flNewProtect", "DWORD"),
                    ("lpflOldProtect", "PDWORD"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "HeapAlloc",
            TypeLibEntry {
                return_ty: "LPVOID",
                params: &[
                    ("hHeap", "HANDLE"),
                    ("dwFlags", "DWORD"),
                    ("dwBytes", "SIZE_T"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "HeapFree",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[
                    ("hHeap", "HANDLE"),
                    ("dwFlags", "DWORD"),
                    ("lpMem", "LPVOID"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetProcessHeap",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "LoadLibraryA",
            TypeLibEntry {
                return_ty: "HMODULE",
                params: &[("lpLibFileName", "LPCSTR")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "LoadLibraryW",
            TypeLibEntry {
                return_ty: "HMODULE",
                params: &[("lpLibFileName", "LPCWSTR")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetProcAddress",
            TypeLibEntry {
                return_ty: "FARPROC",
                params: &[("hModule", "HMODULE"), ("lpProcName", "LPCSTR")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "CreateThread",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[
                    ("lpThreadAttributes", "LPSECURITY_ATTRIBUTES"),
                    ("dwStackSize", "SIZE_T"),
                    ("lpStartAddress", "LPTHREAD_START_ROUTINE"),
                    ("lpParameter", "LPVOID"),
                    ("dwCreationFlags", "DWORD"),
                    ("lpThreadId", "LPDWORD"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "ExitProcess",
            TypeLibEntry {
                return_ty: "void",
                params: &[("uExitCode", "UINT")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "WaitForSingleObject",
            TypeLibEntry {
                return_ty: "DWORD",
                params: &[("hHandle", "HANDLE"), ("dwMilliseconds", "DWORD")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetLastError",
            TypeLibEntry {
                return_ty: "DWORD",
                params: &[],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "SetLastError",
            TypeLibEntry {
                return_ty: "void",
                params: &[("dwErrCode", "DWORD")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetModuleHandleA",
            TypeLibEntry {
                return_ty: "HMODULE",
                params: &[("lpModuleName", "LPCSTR")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetModuleHandleW",
            TypeLibEntry {
                return_ty: "HMODULE",
                params: &[("lpModuleName", "LPCWSTR")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "Sleep",
            TypeLibEntry {
                return_ty: "void",
                params: &[("dwMilliseconds", "DWORD")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetCurrentProcess",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetCurrentProcessId",
            TypeLibEntry {
                return_ty: "DWORD",
                params: &[],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetCurrentThread",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "GetCurrentThreadId",
            TypeLibEntry {
                return_ty: "DWORD",
                params: &[],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "TerminateProcess",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[("hProcess", "HANDLE"), ("uExitCode", "UINT")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "OpenProcess",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[
                    ("dwDesiredAccess", "DWORD"),
                    ("bInheritHandle", "BOOL"),
                    ("dwProcessId", "DWORD"),
                ],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "CreateToolhelp32Snapshot",
            TypeLibEntry {
                return_ty: "HANDLE",
                params: &[("dwFlags", "DWORD"), ("th32ProcessID", "DWORD")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "Process32First",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[("hSnapshot", "HANDLE"), ("lppe", "LPPROCESSENTRY32")],
                calling_conv: "Stdcall",
            },
        );
        lib.insert(
            "Process32Next",
            TypeLibEntry {
                return_ty: "BOOL",
                params: &[("hSnapshot", "HANDLE"), ("lppe", "LPPROCESSENTRY32")],
                calling_conv: "Stdcall",
            },
        );

        // POSIX APIs
        lib.insert(
            "open",
            TypeLibEntry {
                return_ty: "int",
                params: &[
                    ("pathname", "const char *"),
                    ("flags", "int"),
                    ("mode", "mode_t"),
                ],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "read",
            TypeLibEntry {
                return_ty: "ssize_t",
                params: &[("fd", "int"), ("buf", "void *"), ("count", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "write",
            TypeLibEntry {
                return_ty: "ssize_t",
                params: &[("fd", "int"), ("buf", "const void *"), ("count", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "close",
            TypeLibEntry {
                return_ty: "int",
                params: &[("fd", "int")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "malloc",
            TypeLibEntry {
                return_ty: "void *",
                params: &[("size", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "calloc",
            TypeLibEntry {
                return_ty: "void *",
                params: &[("nmemb", "size_t"), ("size", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "realloc",
            TypeLibEntry {
                return_ty: "void *",
                params: &[("ptr", "void *"), ("size", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "free",
            TypeLibEntry {
                return_ty: "void",
                params: &[("ptr", "void *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "memcpy",
            TypeLibEntry {
                return_ty: "void *",
                params: &[("dest", "void *"), ("src", "const void *"), ("n", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "memmove",
            TypeLibEntry {
                return_ty: "void *",
                params: &[("dest", "void *"), ("src", "const void *"), ("n", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "memset",
            TypeLibEntry {
                return_ty: "void *",
                params: &[("s", "void *"), ("c", "int"), ("n", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "strcpy",
            TypeLibEntry {
                return_ty: "char *",
                params: &[("dest", "char *"), ("src", "const char *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "strncpy",
            TypeLibEntry {
                return_ty: "char *",
                params: &[("dest", "char *"), ("src", "const char *"), ("n", "size_t")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "strcmp",
            TypeLibEntry {
                return_ty: "int",
                params: &[("s1", "const char *"), ("s2", "const char *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "strncmp",
            TypeLibEntry {
                return_ty: "int",
                params: &[
                    ("s1", "const char *"),
                    ("s2", "const char *"),
                    ("n", "size_t"),
                ],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "strlen",
            TypeLibEntry {
                return_ty: "size_t",
                params: &[("s", "const char *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "printf",
            TypeLibEntry {
                return_ty: "int",
                params: &[("format", "const char *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "sprintf",
            TypeLibEntry {
                return_ty: "int",
                params: &[("str", "char *"), ("format", "const char *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "snprintf",
            TypeLibEntry {
                return_ty: "int",
                params: &[
                    ("str", "char *"),
                    ("size", "size_t"),
                    ("format", "const char *"),
                ],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "fopen",
            TypeLibEntry {
                return_ty: "FILE *",
                params: &[("pathname", "const char *"), ("mode", "const char *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "fclose",
            TypeLibEntry {
                return_ty: "int",
                params: &[("stream", "FILE *")],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "fread",
            TypeLibEntry {
                return_ty: "size_t",
                params: &[
                    ("ptr", "void *"),
                    ("size", "size_t"),
                    ("nmemb", "size_t"),
                    ("stream", "FILE *"),
                ],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "fwrite",
            TypeLibEntry {
                return_ty: "size_t",
                params: &[
                    ("ptr", "const void *"),
                    ("size", "size_t"),
                    ("nmemb", "size_t"),
                    ("stream", "FILE *"),
                ],
                calling_conv: "cdecl",
            },
        );
        lib.insert(
            "exit",
            TypeLibEntry {
                return_ty: "void",
                params: &[("status", "int")],
                calling_conv: "cdecl",
            },
        );

        lib
    })
}

pub fn match_type_libs(sdb: &mut SemanticDatabase) {
    let lib = get_type_lib();

    // We want to match imports. They are in sdb.facts.binary.imports
    for imp in &sdb.facts.binary.imports {
        let name = imp.value.symbol_name.clone();
        if let Some(entry) = lib.get(name.as_str()) {
            let mut sdb_params = Vec::new();
            for (pname, pty) in entry.params {
                sdb_params.push(SdbParam {
                    name: Some(pname.to_string()),
                    ty: pty.to_string(),
                    location: "unknown".to_string(), // type library doesn't specify physical location
                });
            }

            sdb.interpretations.types.function_types.push(SdbEntry::new(
                SdbFunctionType {
                    name: name.clone(),
                    params: sdb_params,
                    return_ty: entry.return_ty.to_string(),
                    calling_conv: entry.calling_conv.to_string(),
                },
                canary_sdb::ConfidenceVector::base(0.9),
                RecoveryOrigin::Pattern,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canary_sdb::Import;

    #[test]
    fn test_type_lib_matching() {
        let mut sdb = SemanticDatabase::new();
        sdb.facts.binary.imports.push(SdbEntry::new(
            Import {
                symbol_name: "CreateFileW".to_string(),
                address: 0,
                lib_name: "kernel32.dll".to_string(),
            },
            canary_sdb::ConfidenceVector::base(1.0),
            RecoveryOrigin::Exact,
        ));

        match_type_libs(&mut sdb);

        assert_eq!(sdb.interpretations.types.function_types.len(), 1);
        let ft = &sdb.interpretations.types.function_types[0].value;
        assert_eq!(ft.name, "CreateFileW");
        assert_eq!(ft.return_ty, "HANDLE");
        assert_eq!(ft.params.len(), 7);
        assert_eq!(ft.params[0].name.as_deref(), Some("lpFileName"));
    }
}
