// ReSharper disable CppClangTidyClangDiagnosticCastFunctionTypeStrict
#include <windows.h>
#include <iostream>
#include <fstream>
#include <pe-parse/parse.h>

// Prototype for the NtQuerySystemInformation function
using PFN_NtQuerySystemInformation = NTSTATUS(*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// Represents an individual system module
typedef struct _SYSTEM_MODULE
{
    PVOID Reserved1[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

// Contains information about all system modules
typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

/**
 * Translates paths with special prefixes like "\\SystemRoot\\" and "\\??\\"
 * to their canonical form.
 *
 * @param path The original path to be translated.
 * @return Translated path.
 */
std::string translate_path(const std::string& path)
{
    // Handle the "\\SystemRoot\\" prefix
    if (path.find("\\SystemRoot\\") != std::string::npos)
    {
        char system_root[MAX_PATH];
        if (GetEnvironmentVariableA("SystemRoot", system_root, sizeof(system_root)))
        {
            return std::string(system_root) + path.substr(11);
        }
    }

    // Handle the "\\??\\" prefix
    if (path.find("\\??\\") == 0)
    {
        return path.substr(4);
    }

    return path;
}

/**
 * Callback function used by IterImpVAString to check if a module imports a function
 * starting with "FwpsCalloutRegister" from the "FWPKCLNT.SYS" DLL.
 *
 * @param cbd Custom callback data (boolean flag indicating if the module is a WFP callout driver).
 * @param va The virtual address of the import.
 * @param dllName Name of the DLL being imported from.
 * @param funcName Name of the function being imported.
 * @return Always returns 0 to continue iteration.
 */
int iter_imp_va_string_cb(void* cbd, const peparse::VA& va, const std::string& dllName, const std::string& funcName)
{
    auto* is_wfp_callout_driver = static_cast<bool*>(cbd);

    // Check if importing from "FWPKCLNT.SYS"
    if (_stricmp(dllName.c_str(), "FWPKCLNT.SYS") == 0)
    {
        // Check if funcName starts with "FwpsCalloutRegister"
        if (funcName.find("FwpsCalloutRegister") == 0)
        {
            *is_wfp_callout_driver = true;
        }
    }
    return 0;
}

int main()
{
    // Load "ntdll.dll" dynamically
    const HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll)
    {
        std::cerr << "Failed to load ntdll.dll!" << std::endl;
        return -1;
    }

    // Retrieve the address of NtQuerySystemInformation
    const auto nt_query_system_information =
        reinterpret_cast<PFN_NtQuerySystemInformation>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!nt_query_system_information)
    {
        std::cerr << "Failed to get the address of NtQuerySystemInformation!" << std::endl;
        FreeLibrary(ntdll);
        return -1;
    }

    // Get system modules information
    ULONG len = 0;
    nt_query_system_information(11, nullptr, 0, &len);
    const auto mod_info = static_cast<PSYSTEM_MODULE_INFORMATION>(malloc(len));
    nt_query_system_information(11, mod_info, len, &len);

    // Iterate over all system modules
    for (ULONG i = 0; i < mod_info->ModulesCount; i++)
    {
        auto module_name = translate_path(mod_info->Modules[i].ImageName);

        // Parse the module using peparse library
        if (const auto parsed_module = peparse::ParsePEFromFile(module_name.c_str()))
        {
            bool is_wfp_callout = false;
            IterImpVAString(parsed_module, iter_imp_va_string_cb, &is_wfp_callout);

            // Check if the module is a WFP callout driver
            if (is_wfp_callout)
            {
                std::cout << module_name << " highly likely a WFP callout filter: imports FWPKCLNT!FwpsCalloutRegister" << std::endl;
            }

            DestructParsedPE(parsed_module);
        }
    }

    free(mod_info);
    FreeLibrary(ntdll); // Cleanup

    return 0;
}