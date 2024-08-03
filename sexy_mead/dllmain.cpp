#include "hooked_fun.h"
#include <MinHook.h>
#include <vector>

 
EXTERN_C  __declspec(dllexport) auto proxy() -> VOID
{
    return;
}


INT WINAPI hook_messagebox
(
    HWND hWnd,
    LPCWSTR lpText,
    LPCWSTR lpCaption,
    UINT uType
)
{
    return MessageBoxW(hWnd, L"AyeMeh!\n", lpCaption, uType);
}
SHORT WINAPI  hook_get_asynk_key
(
    INT vKey
)
{
    printf("key ->\d%p\n", vKey);
    return GetAsyncKeyState(vKey);
}

NO_INLINE auto init_hook
(

) -> BOOLEAN
{
    MH_STATUS mh_status;
    PVOID api_addr[INT8_MAX] = { NULL };
    HMODULE ntdll_base = NULL; 
    HMODULE kernel32_base = NULL;
    HMODULE kernelbase_base = NULL; 
    HMODULE user32_base = NULL;
    CRC_RUN_INFO crc_rin_inf = { NULL };

    hooked_fun::anti_debug_util anti_deb;
    hooked_fun::crc_file_util anti_crc_file;
    hooked_fun::anti_analisys_util anti_anal; //he-he boy
    hooked_fun::crc_runtime_util crc_runt;
    hooked_fun::anti_vm_util anti_vm;
    hooked_fun::util_list_hook list_hook_util;

    ntdll_base = GetModuleHandleW(L"ntdll.dll"); 
    kernel32_base = GetModuleHandleW(L"kernel32.dll");    
    kernelbase_base = GetModuleHandleW(L"kernelbase.dll");
    user32_base = GetModuleHandleW(L"user32.dll");
 
    mh_status = MH_Initialize();
    if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
    {
        return FALSE;
    }

    //anti-debug
    api_addr[NULL] = GetProcAddress(ntdll_base, "NtQueryInformationProcess");
    api_addr[1] = GetProcAddress(ntdll_base, "NtSetInformationThread");
    api_addr[2] = GetProcAddress(ntdll_base, "NtGetContextThread");
    api_addr[3] = GetProcAddress(user32_base, "GetWindowTextA");
    api_addr[4] = GetProcAddress(kernelbase_base, "CompareStringA");
     
    //anti-crc_file
    api_addr[5] = GetProcAddress(kernel32_base, "CreateFileW");
    list_hook_util.add_crc_file_list(NULL);
 
    //ana-analisys
    api_addr[6] = GetProcAddress(user32_base, "FindWindowA");
    api_addr[7] = GetProcAddress(kernel32_base, "lstrcmpiA");
    api_addr[8] = GetProcAddress(ntdll_base, "RtlAddVectoredExceptionHandler");

    //anti-vm
    api_addr[9] = GetProcAddress(kernel32_base, "GetSystemFirmwareTable");
    api_addr[10] = GetProcAddress(kernelbase_base, "RegOpenKeyExA");
    api_addr[11] = GetProcAddress(kernelbase_base, "RegQueryValueExA"); 
    list_hook_util.add_exit_instr_patch(NULL);
    //anti-sandbox
    api_addr[12] = GetProcAddress(kernelbase_base, "GetModuleHandleA");

    //crc runtime
    api_addr[13] = GetProcAddress(kernelbase_base, "VirtualAlloc");
    list_hook_util.add_crc_run_list(NULL);

    mh_status = MH_Initialize();
    if (mh_status != MH_OK && mh_status != MH_ERROR_ALREADY_INITIALIZED)
    {
        return FALSE;
    }

    anti_deb.clean_peb();
    AddVectoredExceptionHandler(TRUE, crc_runt.veh_hook);

    if (
        MH_CreateHook(api_addr[NULL], anti_deb.query_proc, &hooked_fun::anti_deb.orig_query_proc) != MH_OK ||
        MH_EnableHook(api_addr[NULL]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[1], anti_deb.set_thread, &hooked_fun::anti_deb.orig_set_thread) != MH_OK ||
        MH_EnableHook(api_addr[1]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[2], anti_deb.get_context, &hooked_fun::anti_deb.orig_get_context) != MH_OK ||
        MH_EnableHook(api_addr[2]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[3], anti_deb.get_windows_texta, &hooked_fun::anti_deb.orig_windows_texta) != MH_OK ||
        MH_EnableHook(api_addr[3]) != MH_OK
        )
    {
        return FALSE;
    }

 
    if (
        MH_CreateHook(api_addr[4], anti_deb.compare_stringa, &hooked_fun::anti_deb.orig_compare_stringa) != MH_OK ||
        MH_EnableHook(api_addr[4]) != MH_OK
        )
    {
        return FALSE;
    } 

    if  (
            MH_CreateHook(api_addr[5], anti_crc_file.create_filew, &hooked_fun::crc_file.orig_create_filew) != MH_OK ||
            MH_EnableHook(api_addr[5]) != MH_OK  
        )
    {
        return FALSE;
    }
   

    if (
        MH_CreateHook(api_addr[6], anti_anal.find_windowa, &hooked_fun::anti_monit.orig_find_windowa) != MH_OK ||
        MH_EnableHook(api_addr[6]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[7], anti_anal.strcmpa, &hooked_fun::anti_monit.orig_strcmpa) != MH_OK ||
        MH_EnableHook(api_addr[7]) != MH_OK
        )
    {
        return FALSE;
    }

    
   // Use for get imp loader
    if (
        MH_CreateHook(api_addr[8], anti_anal.add_vector_exc_handler, &hooked_fun::orig_add_vec_handler) != MH_OK ||
        MH_EnableHook(api_addr[8]) != MH_OK
        )
    {
        return FALSE;
    }
    

    if (
        MH_CreateHook(api_addr[9], anti_vm.get_system_firmware_tab, &hooked_fun::anti_vm.orig_get_system_firmware_tab) != MH_OK ||
        MH_EnableHook(api_addr[9]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[10], anti_vm.reg_open_keyexa, &hooked_fun::anti_vm.orig_reg_open_keyexa) != MH_OK ||
        MH_EnableHook(api_addr[10]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[11], anti_vm.query_value_exa, &hooked_fun::anti_vm.orig_query_value_exa) != MH_OK ||
        MH_EnableHook(api_addr[11]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[12], anti_vm.get_mod_handlea, &hooked_fun::anti_vm.orig_getmodule_handlea) != MH_OK ||
        MH_EnableHook(api_addr[12]) != MH_OK
        )
    {
        return FALSE;
    }

    if (
        MH_CreateHook(api_addr[13], crc_runt.virtual_alloc, &hooked_fun::crc_run.orig_virt_alloc) != MH_OK ||
        MH_EnableHook(api_addr[13]) != MH_OK
        )
    {
        return FALSE;
    }    

    //example
    list_hook_util.add_hook_obf_imp(hook_messagebox, NULL, L"user32.dll", "MessageBoxW");
    //list_hook_util.add_hook_obf_imp(hook_get_asynk_key, NULL, L"user32.dll", "GetAsyncKeyState");
    //list_hook_util.add_hook_loader_imp(NULL);
    return TRUE;
 
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        init_hook();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

