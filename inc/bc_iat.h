#pragma once
#include <bc_var.h>
#include <bc_undocumented.h>
#include <bc_peb.h>

#include <xorstr.hpp>

#include <Windows.h>

namespace bc
{
    struct iat
    {
        obfuscated_prim64<decltype(TerminateProcess)*, 0x1337, __LINE__> TerminateProcess;
        obfuscated_prim64<decltype(GetCurrentProcessId)*, 0x1337, __LINE__> GetCurrentProcessId;
        obfuscated_prim64<decltype(QueryPerformanceCounter)*, 0x1337, __LINE__> QueryPerformanceCounter;
        obfuscated_prim64<decltype(GetProcAddress)*, 0x1337, __LINE__> GetProcAddress;
        obfuscated_prim64<decltype(VirtualProtect)*, 0x1337, __LINE__> VirtualProtect;
        obfuscated_prim64<decltype(EnterCriticalSection)*, 0x1337, __LINE__> EnterCriticalSection;
        obfuscated_prim64<decltype(LeaveCriticalSection)*, 0x1337, __LINE__> LeaveCriticalSection;
        obfuscated_prim64<decltype(Sleep)*, 0x1337, __LINE__> Sleep;
        obfuscated_prim64<decltype(GetTickCount64)*, 0x1337, __LINE__> GetTickCount64;
        obfuscated_prim64<decltype(SizeofResource)*, 0x1337, __LINE__> SizeofResource;
        obfuscated_prim64<decltype(SetConsoleTextAttribute)*, 0x1337, __LINE__> SetConsoleTextAttribute;
        obfuscated_prim64<decltype(GetCurrentProcess)*, 0x1337, __LINE__> GetCurrentProcess;
        obfuscated_prim64<decltype(GetStdHandle)*, 0x1337, __LINE__> GetStdHandle;
        obfuscated_prim64<decltype(InitializeCriticalSection)*, 0x1337, __LINE__> InitializeCriticalSection;
        obfuscated_prim64<decltype(FindResourceA)*, 0x1337, __LINE__> FindResourceA;
        obfuscated_prim64<decltype(GetModuleHandleA)*, 0x1337, __LINE__> GetModuleHandleA;
        obfuscated_prim64<decltype(LockResource)*, 0x1337, __LINE__> LockResource;
        obfuscated_prim64<decltype(CreateThread)*, 0x1337, __LINE__> CreateThread;
        obfuscated_prim64<decltype(LoadResource)*, 0x1337, __LINE__> LoadResource;
        obfuscated_prim64<decltype(FindResourceW)*, 0x1337, __LINE__> FindResourceW;
        obfuscated_prim64<decltype(AddVectoredExceptionHandler)*, 0x1337, __LINE__> AddVectoredExceptionHandler;
        obfuscated_prim64<decltype(AllocConsole)*, 0x1337, __LINE__> AllocConsole;
        obfuscated_prim64<decltype(SetConsoleTitleW)*, 0x1337, __LINE__> SetConsoleTitleW;
        obfuscated_prim64<decltype(GetModuleHandleW)*, 0x1337, __LINE__> GetModuleHandleW;
        obfuscated_prim64<decltype(SetUnhandledExceptionFilter)*, 0x1337, __LINE__> SetUnhandledExceptionFilter;
        obfuscated_prim64<decltype(GetFileSize)*, 0x1337, __LINE__> GetFileSize;
        obfuscated_prim64<decltype(GetSystemTimeAsFileTime)*, 0x1337, __LINE__> GetSystemTimeAsFileTime;
        obfuscated_prim64<decltype(GetCurrentThread)*, 0x1337, __LINE__> GetCurrentThread;
        obfuscated_prim64<decltype(GetThreadContext)*, 0x1337, __LINE__> GetThreadContext;
        obfuscated_prim64<decltype(SetThreadContext)*, 0x1337, __LINE__> SetThreadContext;
        obfuscated_prim64<decltype(IsDebuggerPresent)*, 0x1337, __LINE__> IsDebuggerPresent;
        obfuscated_prim64<decltype(ReadFile)*, 0x1337, __LINE__> ReadFile;
        obfuscated_prim64<decltype(VirtualFree)*, 0x1337, __LINE__> VirtualFree;
        obfuscated_prim64<decltype(VirtualAlloc)*, 0x1337, __LINE__> VirtualAlloc;
        obfuscated_prim64<decltype(CreateFileA)*, 0x1337, __LINE__> CreateFileA;
        obfuscated_prim64<decltype(LoadLibraryA)*, 0x1337, __LINE__> LoadLibraryA;
        obfuscated_prim64<decltype(GetCurrentThreadId)*, 0x1337, __LINE__> GetCurrentThreadId;


        obfuscated_prim64<decltype(NtMapViewOfSection)*, 0x1337, __LINE__> NtMapViewOfSection;
        obfuscated_prim64<decltype(NtCreateSection)*, 0x1337, __LINE__> NtCreateSection;
    };

    extern iat IAT;

    __forceinline void init_iat()
    {
        auto peb = peb_walker::tib();

        auto kernel32 = (char*)peb.resolve_module(xorstr_(L"kernel32.dll"));
        auto ntdll = (char*)peb.resolve_module(xorstr_(L"ntdll.dll"));
#define FILL_IAT(M, N) IAT.N = (decltype(N)*)peb.resolve_function(M, xorstr_(#N));

        FILL_IAT(kernel32, TerminateProcess); //TerminateProcess;
        FILL_IAT(kernel32, GetCurrentProcessId); //GetCurrentProcessId;
        FILL_IAT(kernel32, QueryPerformanceCounter); //QueryPerformanceCounter;
        FILL_IAT(kernel32, GetProcAddress); //GetProcAddress;
        FILL_IAT(kernel32, VirtualProtect); //VirtualProtect;
        FILL_IAT(kernel32, EnterCriticalSection); //EnterCriticalSection;
        FILL_IAT(kernel32, LeaveCriticalSection); //LeaveCriticalSection;
        FILL_IAT(kernel32, Sleep); //Sleep;
        FILL_IAT(kernel32, GetTickCount64); //GetTickCount64;
        FILL_IAT(kernel32, SizeofResource); //SizeofResource;
        FILL_IAT(kernel32, SetConsoleTextAttribute); //SetConsoleTextAttribute;
        FILL_IAT(kernel32, GetCurrentProcess); //GetCurrentProcess;
        FILL_IAT(kernel32, GetStdHandle); //GetStdHandle;
        FILL_IAT(kernel32, InitializeCriticalSection); //InitializeCriticalSection;
        FILL_IAT(kernel32, FindResourceA); //FindResourceA;
        FILL_IAT(kernel32, GetModuleHandleA); //GetModuleHandleA;
        FILL_IAT(kernel32, LockResource); //LockResource;
        FILL_IAT(kernel32, CreateThread); //CreateThread;
        FILL_IAT(kernel32, LoadResource); //LoadResource;
        FILL_IAT(kernel32, FindResourceW); //FindResourceW;
        FILL_IAT(kernel32, AddVectoredExceptionHandler); //AddVectoredExceptionHandler;
        FILL_IAT(kernel32, AllocConsole); //AllocConsole;
        FILL_IAT(kernel32, SetConsoleTitleW); //SetConsoleTitleW;
        FILL_IAT(kernel32, GetModuleHandleW); //GetModuleHandleW;
        FILL_IAT(kernel32, SetUnhandledExceptionFilter); //SetUnhandledExceptionFilter;
        FILL_IAT(kernel32, GetFileSize); //GetFileSize;
        FILL_IAT(kernel32, GetSystemTimeAsFileTime); //GetSystemTimeAsFileTime;
        FILL_IAT(kernel32, GetCurrentThread); //GetCurrentThread;
        FILL_IAT(kernel32, GetThreadContext); //GetThreadContext;
        FILL_IAT(kernel32, SetThreadContext); //SetThreadContext;
        FILL_IAT(kernel32, IsDebuggerPresent); //IsDebuggerPresent;
        FILL_IAT(kernel32, ReadFile); //ReadFile;
        FILL_IAT(kernel32, VirtualFree); //VirtualFree;
        FILL_IAT(kernel32, VirtualAlloc); //VirtualAlloc;
        FILL_IAT(kernel32, CreateFileA); //CreateFileA;
        FILL_IAT(kernel32, LoadLibraryA); //LoadLibraryA;
        FILL_IAT(kernel32, GetCurrentThreadId);

        FILL_IAT(ntdll, NtMapViewOfSection);
        FILL_IAT(ntdll, NtCreateSection);
    }
}