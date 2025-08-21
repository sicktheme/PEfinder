#include <iostream>
#include <fstream>
#include <vector>
#include "headers.h"

#define IMAGE_FILE_MACHINE_I386 0x014C //x86
#define IMAGE_FILE_MACHINE_AMD64 0x8664 //x64

#define ALIGN_DOWN(x, align) (x & ~(align-1))
#define ALIGN_UP(x, align) ((x & (align-1))?ALIGN_DOWN(x,align)+align:x)

void testOutPut_(const IMAGE_NT_HEADER32& nt_header64) {
	std::cout << "signature: 0x" << std::hex << nt_header64.signature << std::endl;
	std::cout << "magic: 0x" << nt_header64.optional_header.magic << std::endl;
	std::cout << "linker (major) 0x: " << nt_header64.optional_header.major_linker_version << std::endl;
	std::cout << "linker (minor) 0x: " << nt_header64.optional_header.minor_linker_version << std::endl;
	std::cout << "size of code: 0x" << std::hex << nt_header64.optional_header.size_of_code << std::endl;
	std::cout << "size of init.data: 0x" << std::hex << nt_header64.optional_header.size_of_initialized_data << std::endl;
	std::cout << "size of unitialized data: 0x" << std::hex << nt_header64.optional_header.size_of_uninitialized_data << std::endl;
	std::cout << "entry point: 0x" << std::hex << nt_header64.optional_header.addr_of_entry_point << std::endl;
	std::cout << "base of code: 0x" << std::hex << nt_header64.optional_header.base_of_code << std::endl;
	std::cout << "base of data: 0x" << std::hex << nt_header64.optional_header.base_of_data << std::endl;
	std::cout << "image base: " << nt_header64.optional_header.image_base << std::endl;
	std::cout << "section alignment: " << nt_header64.optional_header.section_alignment << std::endl;
	std::cout << "file alignment: " << nt_header64.optional_header.file_alignment << std::endl;
	std::cout << "os ver. (major): " << nt_header64.optional_header.major_operating_system_version << std::endl;
	std::cout << "os ver. (minor): " << nt_header64.optional_header.minor_operating_system_version << std::endl;
	std::cout << "image ver. (major): " << nt_header64.optional_header.major_image_version << std::endl;
	std::cout << "image ver. (minor): " << nt_header64.optional_header.minor_image_version << std::endl;
	std::cout << "size of image: " << nt_header64.optional_header.size_of_image << std::endl;
	std::cout << "size of headers: " << nt_header64.optional_header.size_of_headers << std::endl;
	std::cout << "checksum: " << nt_header64.optional_header.check_sum << std::endl;
	std::cout << "subsystem: " << nt_header64.optional_header.sub_system << std::endl;
	
	std::cout << "============================================" << std::endl;
	std::cout << "machine: " << std::hex << nt_header64.file_header.machine << std::endl;						//yes
	std::cout << "sections count: " << nt_header64.file_header.number_of_section << std::endl;		//yes
	std::cout << "time date stamp: " << nt_header64.file_header.time_date_stamp << std::endl;		//
	std::cout << "size of options: " << nt_header64.file_header.size_of_optional_header << std::endl;//yes
	std::cout << "characteristics: " << nt_header64.file_header.characteristics << std::endl;			//??
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

	uint16_t sectionOffset = dos_header.e_lfanew + sizeof(uint16_t) + sizeof(IMAGE_FILE_HEADER) + nt_header32.file_header.size_of_optional_header;
	file.seekg(sectionOffset, std::ios::beg);
	//std::cout << sectionOffset; //486 // 1E6

	uint8_t numSections = nt_header32.file_header.number_of_section;
	std::vector<IMAGE_SECTION_HEADER> sections(numSections);

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
			<< ", Size: " << std::dec << sections[i].size_of_raw_data << " bytes" << std::endl;
	}

	//testOutPut_(nt_header32);




	file.close();

	return 0;
}