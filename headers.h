#pragma once

//dos header
//dos stub
//nt signature (1. pe signature. 2. file header. 3. optional header)
//section headers(table).. (section...)

// RVA - Relative Virtual Address. �������� ������������ �������� ������ �������� ������ � ������. ���� PE �������� �� ������ 0x400000, RVA ����� ����� 0x1000
// �� ����� ����� ����� 0x401000

// VA - Virtual Address. ���������� ����� � ������ (VA = ImageBase + RVA)
// Import/Export Function.
// IMPORT - IMAGE_IMPORT_DESCRIPTOR - ������ �������, ������� PE-���� ���������� �� ������ DLL
// EXPORT - IMAGE_EXPORT_DESCRIPTOR - ������ �������, ������� PE-���� ������������� ������ ����������.

//RELOCATION - IMAGE_BASE_RELOCATION - ���� PE �� ����� ����������� �� ���������������� ������ (image base), ������ �������������� � ������� ���� �������.
//IMAGE_RESOURCE_DIRECTORY - ������, ������, ���������� ���� � ������ ������, ���������� � PE.

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERLOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
//#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7 (x86)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECOTRY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

/*struct IMAGE_DOS_HEADER;
struct IMAGE_FILE_HEADER;
struct IMAGE_OPTIONAL_HEADER;
struct IMAGE_DATA_DIRECTORY;
struct IMAGE_NT_HEADER;
struct IMAGE_SECTION_HEADER;*/

#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER {
	uint16_t e_magic;	// = MZ (0x5A4D)
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_lp;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew;	// ��������� �� �������� �� PE. PE\x0\x0. (0x3C) 
} IMAGE_DOS_HEADER;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_FILE_HEADER { // COFF
	uint16_t machine;					// type PC
	uint16_t number_of_section;			// ���-�� ��������
	uint32_t time_date_stamp;			// ����� �������� �����
	uint32_t pointer_to_symbol_table;	// �������� ����� ������� �������� COFF. (������ ���� 0)
	uint32_t number_of_symbols;			// ���-�� ������� � ������� �������� (������ ���� 0)
	uint16_t size_of_optional_header;	// ������ ��������������� ��������� (������ ���� 0)
	uint16_t characteristics;			// �����, ����������� �������� �����
} IMAGE_FILE_HEADER;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_DATA_DIRECTRY {
	uint32_t virtual_addr;						// RVA �� �������, ������� ������������� ������� �������
	uint32_t size;								// ������ ������� � ������
} IMAGE_DATA_DIRECTORY;
#pragma pack(pop)

/*typedef struct _IMAGE_OPTIONAL_HEADER32 {
	uint16_t magic;
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialiized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t addr_of_entry_point;				// RVA ����� ����� (������ .text)
	uint32_t base_of_code;
	uint32_t base_of_data;
	uint32_t image_base;						// ���������������� ����� �������� (��������, 0x400000)
	uint32_t section_alignment;					// ������������ ������ � ������ (������ 0x1000)
	uint32_t file_alignment;					// ������������ � ����� (��������, 0x200)
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;						// ����� ������ ������ � ������
	uint32_t size_of_headers;
	uint32_t check_sum;
	uint16_t sub_system;
	uint16_t dll_characteristics;
	uint32_t size_of_stack_reserve;
	uint32_t size_of_stack_commit;
	uint32_t size_of_heap_reserve;
	uint32_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	IMAGE_DATA_DIRECTORY data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;*/

/*typedef struct _IMAGE_OPTIONAL_HEADER64 {
	uint16_t magic;
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialiized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t addr_of_entry_point;				// RVA ����� ����� (������ .text)
	uint32_t base_of_code;
	uint32_t base_of_data;
	uint32_t image_base;						// ���������������� ����� �������� (��������, 0x400000)
	uint32_t section_alignment;					// ������������ ������ � ������ (������ 0x1000)
	uint32_t file_alignment;					// ������������ � ����� (��������, 0x200)
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;						// ����� ������ ������ � ������
	uint32_t size_of_headers;
	uint32_t check_sum;
	uint16_t sub_system;
	uint16_t dll_characteristics;
	uint32_t size_of_stack_reserve;
	uint32_t size_of_stack_commit;
	uint32_t size_of_heap_reserve;
	uint32_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	IMAGE_DATA_DIRECTORY data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;*/

#pragma pack(push, 1)
typedef struct _IMAGE_OPTIONAL_HEADER32 { // // Optional-header 32x
	uint16_t magic;							// 0x10b - 32x/ 0x20b - 64x (pe32+)
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t addr_of_entry_point;			// RVA
	uint32_t base_of_code;					// RVA .code 
	uint32_t base_of_data;					// RVA .data
	uint32_t image_base;					// ������� ����� ��������
	uint32_t section_alignment;				// ������ ������������ ������ ��� �������� � ����������� ������ (� ������)
	uint32_t file_alignment;				// ������ ������������ ������ ������ ����� (� ������)
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;					// ������ ����� � ������, ������� ��� ��������� (� ������)
	uint32_t size_of_headers;				// ������ ���� ��������� ����������� �� filealigment
	uint32_t check_sum;
	uint16_t sub_system;
	uint16_t dll_characteristics;
	uint32_t size_of_stack_reserve;
	uint32_t size_of_stack_commit;
	uint32_t size_of_heap_reserve;
	uint32_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;		// ���������� ��������� � ������� ����������
	//IMAGE_DATA_DIRECTORY data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];	// ������� ������ (VA+size)
} IMAGE_OPTIONAL_HEADER32;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_OPTIONAL_HEADER64 {	// Optional-header 64x
	uint16_t magic;
	uint8_t major_linker_version;
	uint8_t minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t addr_of_entry_point;			
	uint32_t base_of_code;
	uint32_t base_of_data;
	uint64_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32_version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t check_sum;
	uint16_t sub_system;
	uint16_t dll_characteristics;
	uint64_t size_of_stack_reserve;
	uint64_t size_of_stack_commit;
	uint64_t size_of_heap_reserve;
	uint64_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	//IMAGE_DATA_DIRECTORY data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_NT_HEADERS32 {		// PE-Header 32x
	uint32_t signature;						// PE signature (start PE) (0x00004550)
	IMAGE_FILE_HEADER file_header;			// (information for architecture, � ��) COFF
	IMAGE_OPTIONAL_HEADER32 optional_header;	// (�������, ����� �����, RVA, ������� �������/��������)
} IMAGE_NT_HEADER32;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_NT_HEADERS64 {		// PE-Header 64x
	uint32_t signature;
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER64 optional_header;
} IMAGE_NT_HEADER64;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _IMAGE_SECTION_HEADER {
	uint8_t name[IMAGE_SIZEOF_SHORT_NAME]; // �������� ������
	union {
		uint16_t physical_addr;	// ����� �����
		uint16_t virtual_size;	// ����� ������ ������� ��� �������� � ������ � ������. ���� ������ size_of_raw_data �� ����������� ������
	} misc;
	uint32_t virtual_addr;		// ����� ������� ����� ��� �������� � ������
	uint32_t size_of_raw_data;	// ������ ������������������ ������ �� ����� � ������ (���� ������ ��� virtual size, ����������� ����� ������� ����������� ������)
	uint32_t pointer_to_raw_data;	//��������� �� ������ �������� � ����� COFF.
	uint32_t pointer_to_relocations;	// ����, ��������� �� ������ ������� ����������� ��� �������
	uint32_t pointer_to_linenumbers;	// ��������� �� ������ ��������� ������� �������
	uint16_t number_of_relocations;		// ���������� ������� � ����������� ��� �������
	uint16_t number_of_linenumbers;		// ���������� ��������� ������� ��� �������
	uint32_t characteristics;			// ��������������
} IMAGE_SECTION_HEADER;
#pragma pack(pop)