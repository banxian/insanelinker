#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <map>
#include <sys/stat.h>
#include "AddonFuncUnt.h"
#include "utilunix.h"
#include "elfio/elfio.hpp"
#include "armstub.h"
#include "ntypedefs.h"
#ifdef _WIN32
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#define strcasecmp _stricmp
#endif


using namespace ELFIO;

typedef std::vector< unsigned char > ByteArray;
struct VirtualSection {
    unsigned addr;
    std::string name;
    ByteArray content;
};

enum SymbolTypeEnum {
    stARM,
    stThumb,
    stData,
    stUnkown
};

enum SymbolSectionEnum
{
    ssText,
    ssConst,
    ssData,
    ssBss,
    ssUnkown
};

struct SymbolItem {
    SymbolTypeEnum type;
    unsigned addr;
    unsigned size; // 0?
    bool global;
    bool local;
    bool weak;
    bool undef;
    SymbolSectionEnum sect;
    Elf_Half sectindex;
    std::string name;
};

typedef std::map < std::string, SymbolItem > SymbolMap;

enum LinkTypeEnum {
    ltText,
    ltConst,
    ltData,
    ltBss
};

struct LinkItem {
    LinkTypeEnum type;
    unsigned destaddr;
    unsigned srcaddr;
    unsigned srcsect;
    unsigned size;
};

typedef std::vector < LinkItem > LinkArray;


LinkTypeEnum sectiontypetolinktype(SymbolSectionEnum sse);
bool locatesymbolbyaddr(SymbolMap& symbols, unsigned addr, unsigned sectindex, SymbolMap::iterator& iter);
bool findlinkpartsbyoffset(LinkArray& linkarray, unsigned offset, unsigned section, LinkArray::const_iterator& lit);
SymbolMap loadmapfromtxt(const wchar_t* path);
void printfreespace( exhdr_CodeSetInfo* exheader );
void printexclamatorymark();


int wmain(int argc, const wchar_t *argv[])
{
    const wchar_t* exheaderpath = NULL;
    const wchar_t* exheaderoutpath = NULL;
    const wchar_t* symbolspath = NULL;
    const wchar_t* outputpath = NULL;
    const wchar_t* inputpath = NULL;
    const wchar_t* objectpath = NULL;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        if (beginwith(argv[i], L"--exheader=")) {
            exheaderpath = &(argv[i][sizeof "--exheader=" - 1]);
        } else if (beginwith(argv[i], L"--newexheader=")) {
            exheaderoutpath = &(argv[i][sizeof "--newexheader=" - 1]);
        } else if (beginwith(argv[i], L"--symbols=")) {
            symbolspath = &(argv[i][sizeof "--symbols=" - 1]);
        } else if (wcscmp(argv[i], L"-o") == 0) {
            outputpath = argv[++i];
        }else if (wcscmp(argv[i], L"-i") == 0) {
            inputpath = argv[++i];
        } else if (wcscmp(argv[i], L"-v") == 0) {
            verbose = true;
        } else {
            // both input
            objectpath = argv[i];
        }
    }
    if (exheaderpath == NULL || inputpath == NULL || outputpath == NULL || objectpath == NULL) {
        printf("Usage: insanelinker -i code.bin -o code_insane.bin --exheader=exheader.bin --newexheader=exheader_insane.bin --symbols=idaexp.txt MH4GExporter.o\n");
    }

    elfio reader;
    if (reader.load(objectpath) == false) {
        printexclamatorymark();
        printf("Can't find or process object file %S\n", objectpath);
        return 4;
    }
    Elf_Half sec_num = reader.sections.size();
    VirtualSection textsect, constsect, datasect, bsssect;
    int textsectindex = -1, constsectindex = -1, datasectindex = -1, bsssectindex = -1, undefsectindex = -1, symbolsectionindex = -1;
    SymbolMap localsymbols;
    SymbolMap exefssymbols = loadmapfromtxt(symbolspath); // from symbols.txt

    exhdr_CodeSetInfo* exheader = 0;
    int exheadersize = readallcontent(exheaderpath, (void**)&exheader);

    if (exheadersize == 0) {
        printexclamatorymark();
        printf("Can't read exheader for codebin\n");
        return 5;
    }

    printf("free spaces before linking:\n");
    printfreespace(exheader);
    printf("============================================================\n");

    // get content loop.
    for ( int i = 0; i < sec_num; ++i ) {
        section* psec = reader.sections[i];
        Elf_Word secflags = psec->get_flags();
        if (psec->get_type() == SHT_PROGBITS && secflags == (SHF_EXECINSTR | SHF_ALLOC)) {
            // .text, from address 0
            textsect.addr = psec->get_address();
            textsect.name = psec->get_name();
            textsect.content.insert(textsect.content.end(), psec->get_data(), psec->get_data() + psec->get_size());
            textsectindex = i;
        }
        if (psec->get_type() == SHT_PROGBITS && ((secflags & SHF_ALLOC) && ((secflags & (~(SHF_ALLOC | SHF_MERGE | SHF_STRINGS))) == 0))) {
            // .rodata
            constsect.addr = psec->get_address();
            constsect.name = psec->get_name();
            constsect.content.insert(constsect.content.end(), psec->get_data(), psec->get_data() + psec->get_size());
            constsectindex = i;
        }
        if (psec->get_type() == SHT_PROGBITS && secflags == (SHF_WRITE | SHF_ALLOC)) {
            // .data
            datasect.addr = psec->get_address();
            datasect.name = psec->get_name();
            datasect.content.insert(datasect.content.end(), psec->get_data(), psec->get_data() + psec->get_size());
            datasectindex = i;
        }
        if (psec->get_type() == SHT_NOBITS && secflags == (SHF_WRITE | SHF_ALLOC)) {
            // .bss
            bsssect.addr = psec->get_address();
            bsssect.name = psec->get_name();
            bsssect.content.resize(psec->get_size());//.insert(bsssect.content.end(), psec->get_data(), psec->get_data() + psec->get_size());
            bsssectindex = i;
        }
        if (psec->get_type() == SHT_NULL && secflags == 0) {
            // extern
            undefsectindex = i;
        }
    }
    for ( int i = 0; i < sec_num; ++i ) {
        section* psec = reader.sections[i];
        // Check section type
        if ( psec->get_type() == SHT_SYMTAB ) {
            symbolsectionindex = i;
            const symbol_section_accessor symbols( reader, psec );
            if (verbose) {
                printf("%d unmerged symbols in object file\n", symbols.get_symbols_num());
            }
            // due hash table lack on elfio
            for ( unsigned int j = 0; j < symbols.get_symbols_num(); ++j ) {
                std::string   name;
                Elf64_Addr    value;
                Elf_Xword     size;
                unsigned char bind;
                unsigned char type;
                Elf_Half      section_index;
                unsigned char other;

                // Read symbol properties
                symbols.get_symbol( j, name, value, size, bind, type, section_index, other );
                if (verbose) {
                    printf("value: 0x%llX, size: 0x%llX, bind: %d, type: %d, section_index: %d, other: %d, name: %s\n",  value, size, bind, type, section_index, other, name.c_str());
                }
                if (name.empty() == false && name.compare("$a") != 0 && name.compare("$t") != 0 && name.compare("$d") != 0) {
                    SymbolItem item;
                    item.name = name;
                    item.undef = section_index == undefsectindex;
                    item.global = bind == STB_GLOBAL;
                    item.local = bind == STB_LOCAL;
                    item.type = stUnkown;
                    item.addr = value;
                    item.size = size;
                    item.sect = ssUnkown;
                    item.sectindex = section_index;
                    if (section_index == textsectindex) {
                        item.sect = ssText;
                    } else if (section_index == datasectindex) {
                        item.sect = ssData;
                    } else if (section_index == bsssectindex) {
                        item.sect = ssBss;
                    } else if (section_index == constsectindex) {
                        item.sect = ssConst;
                    }

                    localsymbols.insert(make_pair(name, item));
                }
            } // enum symbol
            // once more for mark $a $t $d
            for ( unsigned int j = 0; j < symbols.get_symbols_num(); ++j ) {
                std::string   name;
                Elf64_Addr    value;
                Elf_Xword     size;
                unsigned char bind;
                unsigned char type;
                Elf_Half      section_index;
                unsigned char other;

                symbols.get_symbol( j, name, value, size, bind, type, section_index, other );
                if (name.compare("$a") == 0 || name.compare("$t") == 0 || name.compare("$d") == 0) {
                    unsigned addr = value;
                    if (name.compare("$t") == 0) {
                        addr &= ~1;
                    }
                    SymbolMap::iterator iter;
                    if (locatesymbolbyaddr(localsymbols, addr, section_index, iter)) {
                        if (name.compare("$a") == 0) {
                            iter->second.type = stARM;
                        }
                        if (name.compare("$t") == 0) {
                            iter->second.type = stThumb;
                        }
                        if (name.compare("$d") == 0) {
                            iter->second.type = stData;
                        }
                    }
                }
            }
        }
    }
    // Build list
    LinkArray linkarray;
    for (SymbolMap::const_iterator it = localsymbols.begin(); it != localsymbols.end(); it++) {
        // replace exists text/data/bss
        if (it->first.compare(0, sizeof("_il_patch") - 1, "_il_patch") == 0) {
            LinkItem item;
            item.type = sectiontypetolinktype(it->second.sect);
            item.srcaddr = it->second.addr;
            item.srcsect = it->second.sectindex;
            item.size = it->second.size;
            SymbolMap::const_iterator preset = exefssymbols.find(it->first);
            if (preset != exefssymbols.end()) {
                item.destaddr = preset->second.addr;
                linkarray.push_back(item);
            }
        }
        // TODO: multi-addon mark in multi object file
        if (it->first.compare(0, sizeof("_il_addon") - 1, "_il_addon") == 0) {
            LinkItem item;
            item.type = sectiontypetolinktype(it->second.sect);
            item.srcaddr = it->second.addr;
            item.srcsect = it->second.sectindex;
            item.size = it->second.size;
            switch (item.type) {
            case ltText:
                item.destaddr = exheader->text.address + exheader->text.codeSize;                
                break;
            case ltConst:
                item.destaddr = exheader->rodata.address + exheader->rodata.codeSize;                
                break;
            case ltData:
                item.destaddr = exheader->data.address + exheader->data.codeSize;
                break;
            case ltBss:
                item.destaddr = exheader->data.address + exheader->data.codeSize + exheader->bssSize;
                break;
            }

            if (item.type != ltData) {
                linkarray.push_back(item);
            } else {
                printexclamatorymark();
                printf("Error found on pre-check %s.\n", it->first.c_str());
                printf("No space between RW end and ZI begin, by design.\n");
                printf("You have to prevent .data expanding.\n");
            }
        }
    }
    printf("normalized %d local symbols in object file\n", localsymbols.size());
    printf("loaded %d symbols from codebin file\n", exefssymbols.size());
    // patch relocation entries before link
    int unsolvedreloc = 0, unsolvedsymbol = 0;
    for ( int i = 0; i < sec_num; ++i ) {
        section* psec = reader.sections[i];
        // relocate text?
        if (psec->get_type() == SHT_REL) {
            VirtualSection& worksect = textsect;
            int worksectindex = textsectindex;
            if (psec->get_name() == std::string(".rel") + constsect.name) {
                worksect = constsect;
                worksectindex = constsectindex;
            } else if (psec->get_name() == std::string(".rel") + datasect.name) {
                worksect = datasect;
                worksectindex = datasectindex;
            } else if (psec->get_name() == std::string(".rel") + bsssect.name) {
                //worksect = bsssect;
                printf("Unused relocate section %s for bss found, bypass.\n", psec->get_name().c_str());
                continue;
            } else if (psec->get_name() != std::string(".rel") + textsect.name) {
                printf("Unexpected relocate section %s, bypass.\n", psec->get_name().c_str());
                continue;
            }
            const relocation_section_accessor relocs(reader, psec);
            printf("%s have %d relocations\n", psec->get_name().c_str(), relocs.get_entries_num());
            for (unsigned j = 0; j < relocs.get_entries_num(); j++) {
                Elf64_Addr  offset;
                Elf64_Addr  symbolValue;
                std::string symbolName;
                Elf_Word    type;
                Elf_Sxword  addend;
                Elf_Sxword  calcValue;
                Elf_Half destsectindex = -1;
                if (relocs.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue)) {
                    Elf_Word symbolindex;
                    relocs.get_entry( j, offset, symbolindex, type, addend );
                    // Find the symbol
                    Elf_Xword     size;
                    unsigned char bind;
                    unsigned char symbolType;
                    Elf_Half      section;
                    unsigned char other;

                    symbol_section_accessor symbols( reader, reader.sections[symbolsectionindex] );
                    if (symbols.get_symbol( symbolindex, symbolName, symbolValue, size, bind, symbolType, section, other ) ){
                        destsectindex = section;
                    }
                }
                if (verbose) {
                    printf("offset: 0x%llX, symbolValue: 0x%llX, type: %d, addend: 0x%llX, calcValue: 0x%llX, symbolName: %s\n", offset, symbolValue, type, addend, calcValue, symbolName.c_str());
                }

                // first local, then external, first weak?
                LinkArray::const_iterator slit;
                if (findlinkpartsbyoffset(linkarray, offset, worksectindex, slit)) {
                    // okay
                    // local
                    SymbolMap::const_iterator llabel = localsymbols.find(symbolName);
                    bool localfixed = false;
                    if (llabel != localsymbols.end() && llabel->second.undef == false) {
                        // need in any linkpart
                        LinkArray::const_iterator dlit;
                        if (findlinkpartsbyoffset(linkarray, llabel->second.addr, llabel->second.sectindex, dlit)) {
                            // okay do
                            unsigned combinedaddr = llabel->second.addr - dlit->srcaddr + dlit->destaddr;
                            std::string sectionname = reader.sections[llabel->second.sectindex]->get_name();
                            bool overflowed = false;
                            if (type == R_ARM_ABS32) {
                                // simple
                                // need add sect base addr
                                // TODO: need add offset?!
                                unsigned origdelta = *(unsigned*)(worksect.content.data() + offset);
                                if (origdelta) {
                                    *(unsigned*)(worksect.content.data() + offset) = origdelta + combinedaddr;
                                    printf("solved R_ARM_ABS32 to object addr 0x%X, combined addr 0x%X + 0x%X\n", llabel->second.addr, combinedaddr, origdelta);

                                } else {
                                    *(unsigned*)(worksect.content.data() + offset) = combinedaddr;
                                    printf("solved R_ARM_ABS32 to object addr 0x%X, combined addr 0x%X\n", llabel->second.addr, combinedaddr);
                                }
                                localfixed = true;
                            } else if (type == R_ARM_CALL) {
                                if (fillbcblcblxarm((worksect.content.data() + offset), combinedaddr - (slit->destaddr + 8 + offset - slit->srcaddr), llabel->second.type == stThumb, &overflowed)) {
                                    printf("solved R_ARM_CALL to object addr 0x%X, combined addr 0x%X\n", llabel->second.addr, combinedaddr);
                                    localfixed = true;
                                } else if (overflowed) {
                                    printf("Distance overflowed in R_ARM_CALL\n");
                                    unsolvedreloc++;
                                } else {
                                    printf("Unknown opcode in R_ARM_CALL\n");
                                    unsolvedreloc++;
                                }
                            } else if (type == R_ARM_JUMP24) {
                                if (fillbcblcblxarm((worksect.content.data() + offset), combinedaddr - (slit->destaddr + 8 + offset - slit->srcaddr), llabel->second.type == stThumb, &overflowed)) {
                                    printf("solved R_ARM_JUMP24 to object addr 0x%X, combined addr 0x%X\n", llabel->second.addr, combinedaddr);
                                    localfixed = true;
                                } else if (overflowed) {
                                    printf("Distance overflowed in R_ARM_JUMP24 to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                } else {
                                    printf("Unknown R_ARM_JUMP24 to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                }
                            } else if (type == R_ARM_THM_CALL) {
                                if (fillblblxthumb1((worksect.content.data() + offset), combinedaddr - (slit->destaddr + 4 + offset - slit->srcaddr), llabel->second.type == stARM, &overflowed)) {
                                    printf("solved R_ARM_THM_CALL to object addr 0x%X, combined addr 0x%X\n", llabel->second.addr, combinedaddr);
                                    localfixed = true;
                                } else if (overflowed) {
                                    printf("Distance overflowed in R_ARM_THM_CALL to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                } else {
                                    printf("Unknown R_ARM_THM_CALL to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                }
                            } else if (type == R_ARM_THM_JUMP11) {
                                if (fillb11b8thumb1((worksect.content.data() + offset), combinedaddr - (slit->destaddr + 4 + offset - slit->srcaddr), &overflowed)) {
                                    printf("solved R_ARM_THM_JUMP11 to object addr 0x%X, combined addr 0x%X\n", llabel->second.addr, combinedaddr);
                                    localfixed = true;
                                } else if (overflowed) {
                                    printf("Distance overflowed in R_ARM_THM_JUMP11 to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                } else {
                                    printf("Unknown R_ARM_THM_JUMP11 to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                }
                            } else if (type == R_ARM_THM_JUMP8) {
                                if (fillb11b8thumb1((worksect.content.data() + offset), combinedaddr - (slit->destaddr + 4 + offset - slit->srcaddr), &overflowed)) {
                                    printf("solved R_ARM_THM_JUMP8 to object addr 0x%X, combined addr 0x%X\n", llabel->second.addr, combinedaddr);
                                    localfixed = true;
                                } else if (overflowed) {
                                    printf("Distance overflowed in R_ARM_THM_JUMP8 to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                } else {
                                    printf("Unknown R_ARM_THM_JUMP8 to object addr %X\n", llabel->second.addr);
                                    unsolvedreloc++;
                                }
                            } else {
                                printf("Unsupported relocation type: %d\n", type);
                                unsolvedreloc++;
                            }
                        } else {
                            printexclamatorymark();
                            printf("Destination symbol 0x%X [%s] in object file is outside codebin, you need place your goodies into any _il_addon/size pair.\n", llabel->second.addr, symbolName.c_str());
                            unsolvedreloc++;
                        }
                    } else if (symbolName.empty() && type == R_ARM_ABS32) {
                        // may local?!
                        // addr is relative delta to section begin!!!
                        // need fix?!
                        unsigned localdestaddr = *(unsigned*)(worksect.content.data() + offset);
                        LinkArray::const_iterator dlit;
                        if (findlinkpartsbyoffset(linkarray, localdestaddr, destsectindex, dlit)) {
                            unsigned combinedaddr = localdestaddr - dlit->srcaddr + dlit->destaddr;
                            *(unsigned*)(worksect.content.data() + offset) = combinedaddr;
                            printf("solved unnamed R_ARM_ABS32 to object addr 0x%X, combined addr 0x%X\n", localdestaddr, combinedaddr);
                            localfixed = true;
                        } else {
                            printexclamatorymark();
                            printf("Relocation destination section %d:0x%X is not in linkage list.\n", destsectindex, localdestaddr);
                            unsolvedreloc++;
                            continue; // but continue?
                        }
                    } else {
                        // find in code bin
                    }
                    if (localfixed) {
                        continue;
                    }

                    // in extern symbols
                    SymbolMap::const_iterator extsym = exefssymbols.find(symbolName);
                    if (extsym != exefssymbols.end()) {
                        bool overflowed = false;
                        // found, patch
                        if (type == R_ARM_ABS32) {
                            // simple
                            // offset?
                            unsigned origdelta = *(unsigned*)(worksect.content.data() + offset);
                            if (origdelta) {
                                *(unsigned*)(worksect.content.data() + offset) = extsym->second.addr + origdelta;
                                printf("solved R_ARM_ABS32 to %X + %X\n", extsym->second.addr, origdelta);
                            } else {
                                *(unsigned*)(worksect.content.data() + offset) = extsym->second.addr;
                                printf("solved R_ARM_ABS32 to %X\n", extsym->second.addr);
                            }
                        } else if (type == R_ARM_CALL) {
                            // A1, BL<c> <label>
                            // A2, BLX <label>
                            bool forceblx = extsym->second.type == stThumb;
                            if (fillbcblcblxarm((worksect.content.data() + offset), extsym->second.addr - (slit->destaddr + 8 + offset - slit->srcaddr), forceblx, &overflowed)) {
                                printf("solved R_ARM_CALL to %X\n", extsym->second.addr);
                            } else if (overflowed) {
                                printf("Distance overflowed in R_ARM_CALL to object addr %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            } else {
                                printf("Unknown opcode in R_ARM_CALL\n");
                                unsolvedreloc++;
                            }
                        } else if (type == R_ARM_JUMP24) {
                            //B       _ZN2nn2fs7UnmountEPKc = B<c> <label>
                            //BLMI    _Z7hardlogPKcz        = BL<c> <label>
                            bool forceblx = extsym->second.type == stThumb;
                            if (fillbcblcblxarm((worksect.content.data() + offset), extsym->second.addr - (slit->destaddr + 8 + offset - slit->srcaddr), forceblx, &overflowed)) {
                                printf("solved R_ARM_JUMP24 to %X\n", extsym->second.addr);
                            } else if (overflowed) {
                                printf("Distance overflowed in R_ARM_JUMP24 to object addr %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            } else {
                                printf("Unknown R_ARM_JUMP24 to %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            }
                        } else if (type == R_ARM_THM_CALL) {
                            // call from thumb code. opcode width is 4 even in thumb1
                            //BLX     _ZN2nn2fs3CTR6MPCore6detail14UserFileSystem9CloseFileEPv
                            //BL      wcslen
                            bool forceblx = extsym->second.type == stARM;
                            if (fillblblxthumb1((worksect.content.data() + offset), extsym->second.addr - (slit->destaddr + 4 + offset - slit->srcaddr), forceblx, &overflowed)) {
                                printf("solved R_ARM_THM_CALL to %X\n", extsym->second.addr);
                            } else if (overflowed) {
                                printf("Distance overflowed in R_ARM_THM_CALL to object addr %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            } else {
                                printf("Unknown R_ARM_THM_CALL to %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            }
                        } else if (type == R_ARM_THM_JUMP11) {
                            if (fillb11b8thumb1((worksect.content.data() + offset), extsym->second.addr - (slit->destaddr + 4 + offset - slit->srcaddr), &overflowed)) {
                                printf("solved R_ARM_THM_JUMP11 to %X\n", extsym->second.addr);
                            } else if (overflowed) {
                                printf("Distance overflowed in R_ARM_THM_JUMP11 to object addr %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            } else {
                                printf("Unknown R_ARM_THM_JUMP11 to %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            }
                        } else if (type == R_ARM_THM_JUMP8) {
                            if (fillb11b8thumb1((worksect.content.data() + offset), extsym->second.addr - (slit->destaddr + 4 + offset - slit->srcaddr), &overflowed)) {
                                printf("solved R_ARM_THM_JUMP8 to %X\n", extsym->second.addr);
                            } else if (overflowed) {
                                printf("Distance overflowed in R_ARM_THM_JUMP8 to object addr %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            } else {
                                printf("Unknown R_ARM_THM_JUMP8 to %X\n", extsym->second.addr);
                                unsolvedreloc++;
                            }
                        } else {
                            printf("Unsupported relocation type: %d\n", type);
                            unsolvedreloc++;
                        }
                    } else {
                        printexclamatorymark();
                        printf("Can't locate symbol [%s] in codebin!\n", symbolName.c_str());
                        unsolvedreloc++;
                        unsolvedsymbol++;
                    }
                } else {
                    unsolvedreloc++;
                    printf("Never go here! Source symbol is not in linklist?!\n");
                }
            }
        }
    }

    if (unsolvedreloc || unsolvedsymbol) {
        printexclamatorymark();
        if (unsolvedreloc) {
            printf("%d relocation record is unsolved.\n", unsolvedreloc);
        }
        if (unsolvedsymbol) {
            printf("%d target symbol is unsolved.\n", unsolvedsymbol);
        }
        if (verbose == false) {
            free(exheader);
            return 7;
        }
    }

    void* code = 0;
    int codesize = readallcontent(inputpath, &code);

    if (codesize == 0) {
        printexclamatorymark();
        printf("Can't read input codebin\n");
        free(exheader);
        return 6;
    }

    unsigned olddatasize = exheader->data.codeSize, oldbsssize = exheader->bssSize;
    for (LinkArray::const_iterator cit = linkarray.begin(); cit != linkarray.end(); cit++) {
        u32 bssbegin = exheader->data.address + exheader->data.codeSize;
        switch (cit->type) {
        case ltText:
            memcpy((char*)code + cit->destaddr - exheader->text.address, textsect.content.data() + cit->srcaddr, cit->size);
            if (cit->destaddr + cit->size - exheader->text.address > exheader->text.codeSize) {
                exheader->text.codeSize = alignby4(cit->destaddr + cit->size - exheader->text.address);
            }
            break;
        case ltConst:
            memcpy((char*)code + cit->destaddr - exheader->rodata.address, constsect.content.data() + cit->srcaddr, cit->size); 
            if (cit->destaddr + cit->size - exheader->rodata.address > exheader->rodata.codeSize) {
                exheader->rodata.codeSize = alignby4(cit->destaddr + cit->size - exheader->rodata.address);
            }
            break;
        case ltData:
            memcpy((char*)code + cit->destaddr - exheader->data.address, datasect.content.data() + cit->srcaddr, cit->size);            
            if (cit->destaddr + cit->size - exheader->data.address > exheader->data.codeSize) {
                exheader->data.codeSize = alignby4(cit->destaddr + cit->size - exheader->data.address);
            }
            break;
        case ltBss:
            //memcpy((char*)code + cit->destaddr - bssbegin, bsssect.content.data() + cit->srcaddr, cit->size);
            if (cit->destaddr + cit->size - bssbegin > exheader->bssSize) {
                exheader->bssSize = alignby4(cit->destaddr + cit->size - bssbegin);
            }
            break;
        }
    }
    printf("\n============================================================\nfree spaces after link:\n");
    // verify exheader
    printfreespace(exheader);
    if (exheader->data.codeSize > olddatasize) {
        printf("data section overflowed 0x%X bytes!\n", olddatasize - exheader->data.codeSize);
    } else {

    }
    if (exheader->bssSize > oldbsssize) {
        printf("bss section increased 0x%X bytes. haven't heard any limit about it.\n", exheader->bssSize - oldbsssize);
    }

    savetofile(outputpath, code, codesize);
    free(code);

    savetofile(exheaderoutpath, exheader, exheadersize);
    free(exheader);

    if (unsolvedreloc || unsolvedsymbol) {
        return 7;
    }

    return 0;
}

bool locatesymbolbyaddr(SymbolMap& symbols, unsigned addr, unsigned sectindex, SymbolMap::iterator& iter)
{
    for (iter = symbols.begin(); iter != symbols.end(); iter++) {
        // TODO: ARM/Thumb?
        if (iter->second.addr == addr && iter->second.undef == false && iter->second.sectindex == sectindex) {
            return true;
        }
    }
    return false;
}

bool findlinkpartsbyoffset(LinkArray& linkarray, unsigned offset, unsigned section, LinkArray::const_iterator& lit)
{
    for (lit = linkarray.begin(); lit != linkarray.end(); lit++) {
        if (offset >= lit->srcaddr && offset < lit->srcaddr + lit->size && lit->srcsect == section) {
            return true;
        }
    }
    return false;
}

SymbolMap loadmapfromtxt(const wchar_t* path)
{
    SymbolMap result;
    if (path == NULL) {
        return result;
    }
    FILE* file = _wfopen(path, L"r");
    if (file == NULL) {
        return result;
    }
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        size_t length = strlen(line);
        while (line[length - 1] == '\n' || line[length - 1] == '\r') {
            line[length - 1] = 0;
            length--;
        }
        SymbolItem item;
        item.size = 0;
        item.undef = false;
        char name[500];
        sscanf(line, "%08X, %d, %s", &item.addr, &item.type, name);
        result.insert(make_pair(std::string(name), item));
    }
    fclose(file);
    return result;
}

void trimstr(char* str)
{
    // Left
    char* curpos = str;
    while (*curpos) {
        char c1 = *curpos;
        // [ ][ ]a
        if (c1 != ' ' && c1 != '\t') {
            memmove(str, curpos, strlen(curpos) + 1);
            break;
        }
        curpos++;
    }
    // Right
    curpos = str + strlen(str) - 1;
    while (*curpos) {
        char c1 = *curpos;
        // b[ ][ ]
        if (c1 != ' ' && c1 != '\t') {
            *(curpos + 1) = 0;
            break;
        }
        curpos--;
    }
}

LinkTypeEnum sectiontypetolinktype(SymbolSectionEnum sse)
{
    switch (sse)
    {
    case ssText:
        return ltText; // RX
    case ssData:
        return ltData; // RW
    case ssBss:
        return ltBss; // ZI
    case ssConst:
        return ltConst; // RO
    default:
        return ltData;
    }
}

void printfreespace( exhdr_CodeSetInfo* exheader ) 
{
    if (exheader->text.codeSize > exheader->text.numMaxPages * 0x1000) {
        printf("text section overflowed 0x%X bytes!\n", exheader->text.codeSize - exheader->text.numMaxPages * 0x1000);
    } else {
        printf("text section have 0x%X bytes gap left\n", exheader->text.numMaxPages * 0x1000 - exheader->text.codeSize);
    }
    if (exheader->rodata.codeSize > exheader->rodata.numMaxPages * 0x1000) {
        printf("rodata section overflowed 0x%X bytes!\n", exheader->rodata.codeSize - exheader->rodata.numMaxPages * 0x1000);
    } else {
        printf("rodata section have 0x%X bytes gap left\n", exheader->rodata.numMaxPages * 0x1000 - exheader->rodata.codeSize);
    }
}

void printexclamatorymark()
{
    printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
}