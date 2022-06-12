#pragma once
#include <Windows.h>

namespace bc
{
	typedef struct _RE_UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} RE_UNICODE_STRING, * PRE_UNICODE_STRING;

	typedef struct _RE_LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		RE_UNICODE_STRING FullDllName;
		RE_UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
		PVOID EntryPointActivationContext;
		PVOID PatchInformation;
	} RE_LDR_DATA_TABLE_ENTRY, * PRE_LDR_DATA_TABLE_ENTRY;

#pragma pack(push, 1)
	typedef struct _RE_PEB_LDR_DATA
	{
		BYTE Reserved1[8];
		PVOID Reserved2[3];
		LIST_ENTRY InMemoryOrderModuleList;
	} RE_PEB_LDR_DATA, * PRE_PEB_LDR_DATA;

	typedef struct _RE_RTL_USER_PROCESS_PARAMETERS
	{
		BYTE Reserved1[16];
		PVOID Reserved2[10];
		RE_UNICODE_STRING ImagePathName;
		RE_UNICODE_STRING CommandLine;
	} RE_RTL_USER_PROCESS_PARAMETERS, * PRE_RTL_USER_PROCESS_PARAMETERS;

	typedef struct _RE_CLIENT_ID
	{
		PVOID UniqueProcess;
		PVOID UniqueThread;
	} RE_CLIENT_ID, * PRE_CLIENT_ID;

	typedef struct _RE_PEB
	{
		// 0x0
		BYTE Reserved1[2];
		// 0x2
		BYTE BeingDebugged;
		// 0x3
		BYTE Reserved2[1];
		// 0x4
		BYTE Padding0[4];
		// 0x8
		PVOID Reserved3[1];
		// 0x10
		PVOID ImageBaseAddress;
		// 0x18
		PRE_PEB_LDR_DATA Ldr;
		// 0x20
		PRE_RTL_USER_PROCESS_PARAMETERS ProcessParameters;
		// 0x28
		PVOID Reserved4[3];
		// 0x40
		PVOID AtlThunkSListPtr;
		// 0x48
		PVOID Reserved5;
		// 0x50
		ULONG Reserved6;
		// 0x54
		BYTE Padding7[4];
		// 0x58
		PVOID Reserved7;
		// 0x60
		ULONG Reserved8;
		// 0x64
		ULONG AtlThunkSListPtr32;
		// 0x68
		PVOID Reserved9[1];
		// 0x70
		ULONG TlsExpansionCounter;
		// 0x74
		BYTE Padding2[4];
		// 0x78
		PVOID TlsBitmap;
		// 0x80
		ULONG TlsBitmapBits[2];
		// 0x88
		PVOID ReadOnlySharedMemoryBase;
		// 0x90
		union
		{
			PVOID ReadOnlySharedMemoryHeap;
			PVOID HotpatchInformation;
			PVOID SparePvoid0;
			PVOID SharedData;
		};
		// 0x98
		PVOID* ReadOnlyStaticServerData;
		// 0xa0
		PVOID AnsiCodePageData;
		// 0xa8
		PVOID OemCodePageData;
		// 0xb0
		PVOID UnicodeCaseTableData;
		// 0xb8
		ULONG NumberOfProcessors;
		// 0xbc
		ULONG NtGlobalFlag;
		// 0xc0
		LARGE_INTEGER CriticalSectionTimeout;
		// 0xc8
		ULONG_PTR HeapSegmentReserve;
		// 0xd0
		ULONG_PTR HeapSegmentCommit;
		// 0xd8
		ULONG_PTR HeapDeCommitTotalFreeThreshold;
		// 0xe0
		ULONG_PTR HeapDeCommitFreeBlockThreshold;
		// 0xe8
		ULONG NumberOfHeaps;
		// 0xec
		ULONG MaximumNumberOfHeaps;
		// 0xf0
		PVOID* ProcessHeaps;
		// 0xf8
		PVOID GdiSharedHandleTable;
		// 0x100
		PVOID ProcessStarterHelper;
		// 0x108
		ULONG GdiDCAttributeList;
		// 0x10c
		BYTE Padding3[4];
		// 0x110
		PVOID LoaderLock;
		// 0x118
		ULONG OSMajorVersion;
		// 0x11c
		ULONG OSMinorVersion;
		// 0x120
		USHORT OSBuildNumber;
		// 0x122
		USHORT OSCSDVersion;
		// 0x124
		ULONG OSPlatformId;
		// 0x128
		ULONG ImageSubsystem;
		// 0x12c
		ULONG ImageSubsystemMajorVersion;
		// 0x130
		ULONG ImageSubsystemMinorVersion;
		// 0x134
		BYTE Padding4[4];
		// 0x138
		BYTE Reserved13[248];
		// 0x230
		void* PostProcessInitRoutine;
		BYTE Reserved11[128];
		PVOID Reserved12[1];
		// 0x2c0
		ULONG SessionId;
	} RE_PEB, * PRE_PEB;

	typedef struct _RE_PROCESS_BASIC_INFORMATION
	{
		PVOID Reserved1;
		PRE_PEB PebBaseAddress;
		PVOID Reserved2[2];
		ULONG_PTR UniqueProcessId;
		PVOID Reserved3;
	} RE_PROCESS_BASIC_INFORMATION;


	typedef struct _RE_TIB
	{
		PVOID SehFrame;
		PVOID StackBase;
		PVOID StackLimit;
		PVOID SubSystemTib;
		PVOID FiberData;
		PVOID ArbitraryDataSlot;
		PVOID LinearAddress;
		PVOID EnvironmentPointer;
		PVOID ProcessId;
		UINT32 ThreadId;
	} RE_TIB, * PRE_TIB;

	typedef struct _GS
	{
		char Padding000[0x30];
		PRE_TIB Teb;
		char Padding001[0x28];
		PRE_PEB Peb;
	} GS, * PGS;
#pragma pack(pop)

	typedef NTSTATUS(*FnNtQueryInformationProcess)(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

	RE_PEB* get_peb();
}