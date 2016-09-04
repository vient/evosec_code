#pragma once

#ifndef PE_H
#define PE_H

#include <vector>
#include <stdint.h>

typedef int8_t CHAR;
typedef uint8_t UCHAR;
typedef int16_t WORD;
typedef uint16_t UWORD;
typedef int32_t LONG;
typedef uint32_t ULONG;

const WORD IMAGE_DOS_SIGNATURE_1 = 0x4D5A;
const WORD IMAGE_DOS_SIGNATURE_2 = 0x5A4D;
const LONG IMAGE_PE_SIGNATURE = 0x4550;

typedef struct _IMAGE_DOS_HEADER
{
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    WORD Machine;
    WORD NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER
{
    WORD Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONG BaseOfData;
    ULONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONG SizeOfStackReserve;
    ULONG SizeOfStackCommit;
    ULONG SizeOfHeapReserve;
    ULONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_PE_HEADERS
{
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_PE_HEADERS, *PIMAGE_PE_HEADERS;

typedef struct _IMAGE_SECTION_HEADER
{
    UCHAR Name[8];
    ULONG Misc;
    ULONG VirtualAddress;
    ULONG SizeOfRawData;
    ULONG PointerToRawData;
    ULONG PointerToRelocations;
    ULONG PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    ULONG Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;



const std::vector<std::pair<std::string, std::vector<unsigned char>>> PESections(const std::vector<unsigned char> &file) noexcept
{
    std::vector<std::pair<std::string, std::vector<unsigned char>>> sections;

    if (file.size() < sizeof(IMAGE_DOS_HEADER))
        return sections;
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(&file[0]);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE_1 && dos_header->e_magic != IMAGE_DOS_SIGNATURE_2)   // not an MZ file
        return sections;

    auto pe_header_offset = dos_header->e_lfanew;
    if (pe_header_offset > 32768)       // almost all valid PE have PE header on offset 0x80
        return sections;

    auto pe_header = reinterpret_cast<const IMAGE_PE_HEADERS*>(&file[pe_header_offset]);
    if (file.size() < pe_header_offset + sizeof(IMAGE_PE_HEADERS))
        return sections;
    if (pe_header->Signature != IMAGE_PE_SIGNATURE)     // not an PE file
        return sections;

    auto MachineID = pe_header->FileHeader.Machine;
    std::cout << std::hex << ' ' << MachineID << ' ';
    if (MachineID != 0x14C && MachineID != (WORD)0x8664)
        return sections;

    if (pe_header->FileHeader.NumberOfSections == 0)
        return sections;

    try
    {
        auto OptHDRSize = pe_header->FileHeader.SizeOfOptionalHeader;
        auto section_ptr = reinterpret_cast<const IMAGE_SECTION_HEADER*>((uint8_t *)&(pe_header->OptionalHeader) + OptHDRSize);
        for (auto i = 0; i < pe_header->FileHeader.NumberOfSections; ++i, ++section_ptr)
        {
            sections.emplace_back();
            sections.back().first = std::string(reinterpret_cast<const char*>(section_ptr->Name));
            sections.back().second = std::vector<unsigned char>(
                file.begin() + section_ptr->PointerToRawData,
                file.begin() + section_ptr->PointerToRawData + section_ptr->SizeOfRawData);
            std::cout << std::endl << "section" << i;
        }
    }
    catch (...)
    {
        sections.clear();
    }
    return sections;
}

#endif // PE_H
