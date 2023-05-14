#pragma once

#include <winnt.h>
#include <algorithm>

typedef struct PEB_LOADER_DATA
{
	UCHAR pad12[ 12 ];
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LOADER_DATA, * PPEB_LOADER_DATA;

typedef struct PEB_NEW
{
#ifdef _WIN64
	UCHAR pad24[ 24 ];
#else
	UCHAR pad12[ 12 ];
#endif
	PEB_LOADER_DATA* Ldr;
} PEB_NEW, * PPEB_NEW;

typedef struct _UNICODE_STRINGG
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRINGG;

typedef struct LOADER_TABLE_ENTRY
{
	LIST_ENTRY				InLoadOrderLinks;
	LIST_ENTRY				InMemoryOrderLinks;
	LIST_ENTRY				InInitializationOrderLinks;
	uintptr_t				DllBase;
	uintptr_t				EntryPoint;
	uint32_t				SizeOfImage;
	UNICODE_STRINGG			FullDllName;
	UNICODE_STRINGG			BaseDllName;
	uint8_t					FlagGroup[ 4 ];
	uint32_t				Flags;
	uint16_t				ObsoleteLoadCount;
	uint16_t				TlsIndex;
	LIST_ENTRY				HashLinks;
	uint32_t				TimeDateStamp;
	uintptr_t				EntryPointActivationContext;
	uintptr_t				Lock;
	uintptr_t				DdagNode;
	LIST_ENTRY				NodeModuleLink;
	uintptr_t				LoadContext;
	uintptr_t				ParentDllBase;
} LOADER_TABLE_ENTRY, * PLOADER_TABLE_ENTRY;

class CMemoryUtils
{
private:
	static void* GetPEBAddress();

public:
	static PIMAGE_DOS_HEADER GetDosHeader( const char* szModule );
	static PIMAGE_NT_HEADERS GetNTHeaders( const char* szModule );
	static PIMAGE_EXPORT_DIRECTORY GetExportDirectory( const char* szModule );

	static void* GetModuleBase( std::string szModule );
	static uintptr_t GetExport( const char* szModule, const char* szExport );
};

// ----------------------------------------------------------------------
// Acquire the address of the PEB.
// ----------------------------------------------------------------------
void* CMemoryUtils::GetPEBAddress()
{
	void* pPEB = nullptr;
#if defined (_WIN64) || defined(_M_X64)
	pPEB = ( void* )__readgsqword( 0x60 );
#else
	pPEB = ( void* )__readfsdword( 0x30 );
#endif

	return pPEB;
}

// ----------------------------------------------------------------------
// Get the IMAGE_DOS_HEADER struct of a module or executable.
// ----------------------------------------------------------------------
PIMAGE_DOS_HEADER CMemoryUtils::GetDosHeader( const char* szModule )
{
	if ( !szModule )
		return nullptr;

	void* pModule = GetModuleBase( szModule );
	if ( !pModule )
		return nullptr;

	return reinterpret_cast< PIMAGE_DOS_HEADER >( pModule );
}

// ----------------------------------------------------------------------
// Get the IMAGE_NT_HEADERS struct of a module or executable.
// ----------------------------------------------------------------------
PIMAGE_NT_HEADERS CMemoryUtils::GetNTHeaders( const char* szModule )
{
	if ( !szModule )
		return nullptr;

	void* pModule = GetModuleBase( szModule );
	if ( !pModule )
		return nullptr;

	PIMAGE_DOS_HEADER pDos = GetDosHeader( szModule );
	if ( !pDos )
		return nullptr;

	return reinterpret_cast< PIMAGE_NT_HEADERS >( ( uintptr_t )pModule + pDos->e_lfanew );
}

// ----------------------------------------------------------------------
// Get the IMAGE_EXPORT_DIRECTORY struct of a module or executable.
// ----------------------------------------------------------------------
PIMAGE_EXPORT_DIRECTORY CMemoryUtils::GetExportDirectory( const char* szModule )
{
	if ( !szModule )
		return nullptr;

	void* pModule = GetModuleBase( szModule );
	if ( !pModule )
		return nullptr;

	PIMAGE_DOS_HEADER pDos = GetDosHeader( szModule );
	if ( !pDos )
		return nullptr;

	PIMAGE_NT_HEADERS pNt = GetNTHeaders( szModule );
	if ( !pNt )
		return nullptr;

	return reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( ( uintptr_t )pModule + pNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
}

// ----------------------------------------------------------------------
// Get the base address of a module or executable via PEB access.
// ----------------------------------------------------------------------
void* CMemoryUtils::GetModuleBase( std::string szModule )
{
	if ( szModule.empty() )
		return nullptr;

	PPEB_NEW pPEB = ( PPEB_NEW )GetPEBAddress();
	if ( !pPEB )
		return nullptr;

	PLIST_ENTRY pListEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;
	PLOADER_TABLE_ENTRY pTable = nullptr;

	while ( pListEntry != &pPEB->Ldr->InLoadOrderModuleList && pListEntry )
	{
		// Initialize table.
		pTable = CONTAINING_RECORD( pListEntry, LOADER_TABLE_ENTRY, InLoadOrderLinks );

		if ( pTable->BaseDllName.Buffer && pTable->BaseDllName.Length )
		{
			std::wstring szBuf = pTable->BaseDllName.Buffer;
			std::string szCurModule = std::string( szBuf.begin(), szBuf.end() );

			// Convert to lowercase. All modules are usually displayed in lowercase in memory.
			std::transform( szCurModule.begin(), szCurModule.end(), szCurModule.begin(), ::tolower );

			if ( szCurModule == szModule )
				return ( void* )pTable->DllBase;
		}

		// Next iteration.
		pListEntry = pListEntry->Flink;
	}
}

// ----------------------------------------------------------------------
// Get the address of an exported function via the PEB access.
// ----------------------------------------------------------------------
uintptr_t CMemoryUtils::GetExport( const char* szModule, const char* szExport )
{
	if ( !szModule || !szExport )
		return 0;

	unsigned char* pBase = ( unsigned char* )GetModuleBase( szModule );
	if ( !pBase )
		return 0;

	PIMAGE_DOS_HEADER pDos = GetDosHeader( szModule );
	if ( !pDos )
		return 0;

	PIMAGE_NT_HEADERS pNt = GetNTHeaders( szModule );
	if ( !pNt )
		return 0;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = GetExportDirectory( szModule );
	if ( !pExportDirectory )
		return 0;

	for ( size_t i = 0; i < pExportDirectory->NumberOfNames; i++ )
	{
		// Get current export name.
		char* szName = ( char* )( pBase + reinterpret_cast< unsigned long* >( pBase + pExportDirectory->AddressOfNames )[ i ] );
		if ( szName )
		{
			if ( !strcmp( szName, szExport ) )
			{
				unsigned short ordinal = reinterpret_cast< unsigned short* >( pBase + pExportDirectory->AddressOfNames )[ i ];
				return ( uintptr_t )( pBase + reinterpret_cast< unsigned long* >( pBase + pExportDirectory->AddressOfFunctions )[ ordinal ] );
			}
		}
	}

	return 0;
}
