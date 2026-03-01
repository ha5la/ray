#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // chmod

const char* name_program_header_type(int type) {
	switch (type) {
	case PT_LOAD: return "PT_LOAD";
	case PT_GNU_STACK: return "PT_GNU_STACK";
	}
	return "UNKNOWN";
}

const char* name_section_header_type(int type) {
	switch (type) {
	case SHT_NULL: return "SHT_NULL";
	case SHT_PROGBITS: return "SHT_PROGBITS";
	case SHT_STRTAB: return "SHT_STRTAB";
	}
	return "UNKNOWN";
}

int is_payload_eligible(const Elf32_Shdr* shdr, const char* names) {
	if (shdr->sh_type != SHT_PROGBITS) return 0;

	static const char* payload_sections[] = {
		".text",
		".rodata",
		".data",
	};
	for (unsigned i = 0; i < sizeof(payload_sections) / sizeof(payload_sections[0]); ++i) {
		if (!strcmp(payload_sections[i], names + shdr->sh_name)) {
			return !0;
		}
	}
	return 0;
}

int main(int argc, char* argv[]) {
	(void)argc;
	int v = !strcmp(argv[1], "-v");
	v && ++argv;
	FILE* fp = fopen(argv[1], "rb");

	Elf32_Ehdr ehdr;
	fread(&ehdr, sizeof(Elf32_Ehdr), 1, fp);
	v && printf("e_entry: 0x%x\n", ehdr.e_entry);
	v && printf("e_phoff: 0x%x %d\n", ehdr.e_phoff, ehdr.e_phoff);
	v && printf("e_shoff: 0x%x %d\n", ehdr.e_shoff, ehdr.e_shoff);
	v && printf("e_phnum: %d\n", ehdr.e_phnum);
	v && printf("e_shnum: %d\n", ehdr.e_shnum);
	v && printf("e_shstrndx: %d\n", ehdr.e_shstrndx);

	const uint32_t payload_entry_point = ehdr.e_entry;

	v && puts("Program headers");
	fseek(fp, ehdr.e_phoff, SEEK_SET);
	for (int i = 0; i < ehdr.e_phnum; ++i) {
		Elf32_Phdr phdr;
		assert(sizeof(Elf32_Phdr) == ehdr.e_phentsize);
		fread(&phdr, sizeof(Elf32_Phdr), 1, fp);
		v && printf("- p_type: %s(0x%x)\n", name_program_header_type(phdr.p_type), phdr.p_type);
		v && printf("  p_offset: 0x%x %d\n", phdr.p_offset, phdr.p_offset);
		v && printf("  p_vaddr: 0x%x\n", phdr.p_vaddr);
		v && printf("  p_paddr: 0x%x\n", phdr.p_paddr);
		v && printf("  p_filesz: 0x%x %d\n", phdr.p_filesz, phdr.p_filesz);
		v && printf("  p_memsz: 0x%x %d\n", phdr.p_memsz, phdr.p_memsz);
		v && printf("  p_flags: %c%c%c\n",
			(phdr.p_flags & PF_R) ? 'R' : ' ',
			(phdr.p_flags & PF_W) ? 'W' : ' ',
			(phdr.p_flags & PF_X) ? 'X' : ' '
		);
		v && printf("  p_align: 0x%x\n", phdr.p_align);
	}

	char* names;
	{
		fseek(fp, ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize, SEEK_SET);
		Elf32_Shdr shdr;
		assert(sizeof(Elf32_Shdr) == ehdr.e_shentsize);
		fread(&shdr, sizeof(Elf32_Shdr), 1, fp);
		names = (char*)malloc(shdr.sh_size);
		fseek(fp, shdr.sh_offset, SEEK_SET);
		fread(names, shdr.sh_size, 1, fp);
	}

	uint32_t payload_addr = 0;
	uint32_t payload_end = 0;
	int payload_section_index = 0;

	char payload_filename[64];
	snprintf(payload_filename, 64, "%s.payload", argv[1]);

	FILE* fp2 = fopen(payload_filename, "wb");

	v && puts("Section headers");
	for (int i = 0; i < ehdr.e_shnum; ++i) {
		Elf32_Shdr shdr;
		assert(sizeof(Elf32_Shdr) == ehdr.e_shentsize);
		fseek(fp, ehdr.e_shoff + i * sizeof(Elf32_Shdr), SEEK_SET);
		fread(&shdr, sizeof(Elf32_Shdr), 1, fp);
		v && printf("- s_name: \"%s\"\n", names + shdr.sh_name);
		v && printf("  s_type: %s(%d)\n", name_section_header_type(shdr.sh_type), shdr.sh_type);
		v && printf("  s_addr: 0x%x\n", shdr.sh_addr);
		v && printf("  s_offset: 0x%x %d\n", shdr.sh_offset, shdr.sh_offset);
		v && printf("  s_size: 0x%x %d\n", shdr.sh_size, shdr.sh_size);
		v && printf("  s_addralign: 0x%x\n", shdr.sh_addralign);
		if (is_payload_eligible(&shdr, names)) {
			if (!payload_section_index) {
				payload_end = payload_addr = shdr.sh_addr;
			}
			const int padding = shdr.sh_addr - payload_end;
			payload_end = shdr.sh_addr + shdr.sh_size;

			char* p = (char*)malloc(padding + shdr.sh_size);
			memset(p, 0, padding);
			fseek(fp, shdr.sh_offset, SEEK_SET);
			fread(p + padding, shdr.sh_size, 1, fp);

			fwrite(p, padding + shdr.sh_size, 1, fp2);

			free(p);

			++payload_section_index;
		}
	}

	fclose(fp2);
	free(names), names = NULL;
	fclose(fp);

	char paq_filename[64];
	snprintf(paq_filename, 64, "%s.paq", argv[1]);

	const int paq_mode = 3;
	const int paq_complexity = 1;

	char onekpaq_command_line[4096];
	snprintf(onekpaq_command_line, 4096, "./onekpaq %d %d %s %s", paq_mode, paq_complexity, payload_filename, paq_filename);
	v && puts(onekpaq_command_line);

	fp = popen(onekpaq_command_line, "r");
	if (!fp) {
		fprintf(stderr, "onekpaq failed\n");
		return !0;
	}

	int paq_offset = -1;
	int paq_shift = -1;
	fscanf(fp, "P offset=%d shift=%d\n", &paq_offset, &paq_shift);
	pclose(fp);

	fp = fopen(paq_filename, "rb");
	int paq_size = -1;
	for (int i = -1;; --i) {
		fseek(fp, i, SEEK_END);
		paq_size = ftell(fp) + 1;
		char ch;
		fread(&ch, 1, 1, fp);
		if (ch) break;
	}

	char output_filename[64];
	snprintf(output_filename, 64, "%s.compact", argv[1]);

	char nasm_command_line[4096];
	char* const end = nasm_command_line + 4096;
	char* p = nasm_command_line;

	p += snprintf(p, end - p, "nasm");
	p += snprintf(p, end - p, " -DPAYLOAD_ADDR=0x%x", payload_addr);
	p += snprintf(p, end - p, " -DPAYLOAD_SIZE=0x%x", payload_end - payload_addr);
	p += snprintf(p, end - p, " -DPAYLOAD_ENTRY_POINT=0x%x", payload_entry_point);
	p += snprintf(p, end - p, " -DPAQ_FILENAME='\"%s\"'", paq_filename);
	p += snprintf(p, end - p, " -DPAQ_OFFSET=%d", paq_offset);
	p += snprintf(p, end - p, " -DPAQ_SIZE=%d", paq_size);
	p += snprintf(p, end - p, " -DONEKPAQ_DECOMPRESSOR_MODE=%d", paq_mode);
	p += snprintf(p, end - p, " -DONEKPAQ_DECOMPRESSOR_SHIFT=%d", paq_shift);
	p += snprintf(p, end - p, " -o%s", output_filename);
	p += snprintf(p, end - p, " ../src/compact-elf.s");
	v && puts(nasm_command_line);

	int ret = system(nasm_command_line);
	if (ret) return ret;

	v && printf("chmod 0755 %s\n", output_filename);
	chmod(output_filename, 0755);
}
