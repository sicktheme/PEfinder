#include <iostream>
#include <fstream>
#include <vector>
#include "headers.h"

#define IMAGE_FILE_MACHINE_I386 0x014C //x86
#define IMAGE_FILE_MACHINE_AMD64 0x8664 //x64

#define ALIGN_DOWN(x, align) (x & ~(align-1))
#define ALIGN_UP(x, align) ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)

void test_output_nt_header(const IMAGE_NT_HEADER32& nt_header32) {
	std::cout << "signature: 0x" << std::hex << nt_header32.signature << std::endl;
	std::cout << "magic: 0x" << nt_header32.optional_header.magic << std::endl;
	std::cout << "linker (major) 0x: " << nt_header32.optional_header.major_linker_version << std::endl;
	std::cout << "linker (minor) 0x: " << nt_header32.optional_header.minor_linker_version << std::endl;
	std::cout << "size of code: 0x" << std::hex << nt_header32.optional_header.size_of_code << std::endl;
	std::cout << "size of init.data: 0x" << std::hex << nt_header32.optional_header.size_of_initialized_data << std::endl;
	std::cout << "size of unitialized data: 0x" << std::hex << nt_header32.optional_header.size_of_uninitialized_data << std::endl;
	std::cout << "entry point: 0x" << std::hex << nt_header32.optional_header.addr_of_entry_point << std::endl;
	std::cout << "base of code: 0x" << std::hex << nt_header32.optional_header.base_of_code << std::endl;
	std::cout << "base of data: 0x" << std::hex << nt_header32.optional_header.base_of_data << std::endl;
	std::cout << "image base: " << nt_header32.optional_header.image_base << std::endl;
	std::cout << "section alignment: " << nt_header32.optional_header.section_alignment << std::endl;
	std::cout << "file alignment: " << nt_header32.optional_header.file_alignment << std::endl;
	std::cout << "os ver. (major): " << nt_header32.optional_header.major_operating_system_version << std::endl;
	std::cout << "os ver. (minor): " << nt_header32.optional_header.minor_operating_system_version << std::endl;
	std::cout << "image ver. (major): " << nt_header32.optional_header.major_image_version << std::endl;
	std::cout << "image ver. (minor): " << nt_header32.optional_header.minor_image_version << std::endl;
	std::cout << "size of image: " << nt_header32.optional_header.size_of_image << std::endl;
	std::cout << "size of headers: " << nt_header32.optional_header.size_of_headers << std::endl;
	std::cout << "checksum: " << nt_header32.optional_header.check_sum << std::endl;
	std::cout << "subsystem: " << nt_header32.optional_header.sub_system << std::endl;
	std::cout << "dll characteristics: " << nt_header32.optional_header.dll_characteristics << std::endl;
	std::cout << "size of stack reservse: " << nt_header32.optional_header.size_of_stack_reserve << std::endl;
	std::cout << "size of stack commit: " << nt_header32.optional_header.size_of_stack_commit << std::endl;
	std::cout << "size of heap reserve: " << nt_header32.optional_header.size_of_heap_reserve << std::endl;
	std::cout << "size of heap commit: " << nt_header32.optional_header.size_of_heap_commit << std::endl;
	std::cout << "loader flags: " << nt_header32.optional_header.loader_flags << std::endl;
	std::cout << "number of RVAS and sizes: " << nt_header32.optional_header.number_of_rva_and_sizes << std::endl;
	/*for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		std::cout << "\ndata directory: " << nt_header32.optional_header.data_directory;
		std::cout << "\ndata directory size: " << nt_header32.optional_header.data_directory->size;
		std::cout << "\ndata directory VA: " << nt_header32.optional_header.data_directory->virtual_addr;
	}*/
	std::cout << "============================================" << std::endl;
	std::cout << "machine: " << std::hex << nt_header32.file_header.machine << std::endl;						//yes
	std::cout << "sections count: " << nt_header32.file_header.number_of_section << std::endl;		//yes
	std::cout << "time date stamp: " << nt_header32.file_header.time_date_stamp << std::endl;		//
	std::cout << "size of options: " << nt_header32.file_header.size_of_optional_header << std::endl;//yes
	std::cout << "characteristics: " << nt_header32.file_header.characteristics << std::endl;			//??
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Not have file in argument\n";
		return 1;
	}

	char* file_path = argv[1];

	//std::cout << file_path;

	std::ifstream file;
	file.open(file_path, std::ios::binary);

	if (!file.is_open()) {
		std::cerr << "Error open file\n";
		file.close();
		return 1;
	}

	IMAGE_DOS_HEADER dos_header;
	file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
	if (!file) {
		std::cerr << "Error read file\n";
		file.close();
		return 1;
	}

	if (dos_header.e_magic != 0x5A4D) {
		std::cerr << "It's not DOS file\n";
		file.close();
		return 1;
	}

	file.seekg(dos_header.e_lfanew, std::ios::beg);
	IMAGE_NT_HEADER32 nt_header32;
	file.read(reinterpret_cast<char*>(&nt_header32), sizeof(nt_header32));

	if (nt_header32.signature != 0x4550) { // подпись
		std::cerr << "It's not PE signature\n";
		file.close();
		return 1;
	}

	//uint32_t optionalHeaderSize = nt_header32.optional_header.size_of_headers;
	//file.seekg(dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + optionalHeaderSize, std::ios::beg);

	//uint16_t sectionOffset = dos_header.e_lfanew + sizeof(uint16_t) + sizeof(IMAGE_FILE_HEADER) + nt_header32.file_header.size_of_optional_header;
	uint16_t sectionTableOffset = dos_header.e_lfanew + sizeof(nt_header32.signature) + sizeof(nt_header32.file_header) + nt_header32.file_header.size_of_optional_header;
	file.seekg(sectionTableOffset, std::ios::beg);
	std::cout << sectionTableOffset; //486 // 1E6

	uint8_t numSections = nt_header32.file_header.number_of_section;
	std::vector<IMAGE_SECTION_HEADER> sections(numSections);

	test_output_nt_header(nt_header32);

	std::cout << "|===============================================|\n";
	std::cout << sectionTableOffset << std::endl;
	std::cout << nt_header32.file_header.size_of_optional_header << std::endl;
	std::cout << "hex:\n";
	std::cout << std::hex << sectionTableOffset << std::endl;
	std::cout << std::hex << nt_header32.file_header.size_of_optional_header << std::endl;
	std::cout << "|===============================================|\n";

	for (uint8_t i = 0; i < numSections; i++) {
		file.read(reinterpret_cast<char*>(&sections[i]), sizeof(IMAGE_SECTION_HEADER));
		if (!file) {
			std::cerr << "Error reading section #" << i << std::endl;
			break;
		}
		std::string name((char*)sections[i].name, 8);
		std::cout << "Section: " << i << ": " << name
			<< ", VA: 0x" << std::hex << sections[i].virtual_addr
			<< ", RAW: 0x" << std::hex << sections[i].pointer_to_raw_data
			<< ", Size: " << std::dec << sections[i].size_of_raw_data << " bytes"
			<< ", Characteristics: 0x" << std::hex << sections[i].characteristics
			<< ", Physical address: 0x" << std::hex << sections[i].misc.physical_addr
			<< ", Virtual size: 0x" << std::hex << sections[i].misc.virtual_size << std::endl;
	}

	/*for (uint8_t i = 0; i < numSections; ++i) {
		if (!file.read(reinterpret_cast<char*>(&sections[i]), sizeof(IMAGE_SECTION_HEADER))) {
			std::cerr << "Failed to read section " << i << std::endl;
			break;
		}

		char sectionName[9] = { 0 };
		memcpy(sectionName, sections[i].name, 8);
		sectionName[8] = '\0';

		std::cout << "Section " << i << ": " << sectionName
			<< ", VA: 0x" << std::hex << sections[i].virtual_addr
			<< ", RAW: 0x" << std::hex << sections[i].pointer_to_raw_data
			<< ", Size: " << std::dec << sections[i].size_of_raw_data << " bytes"
			<< ", characteristics: 0x" << std::hex << sections[i].characteristics << std::endl;
	}*/


	file.close();

	return 0;
}