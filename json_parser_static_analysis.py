#!/usr/bin/env python
# coding: utf-8

# In[341]:


import os
import sys
# from elftools.elf.elffile import ELFFile
# from elftools.elf.sections import SymbolTableSection
# from elftools.elf.descriptions import describe_sh_flags, describe_p_flags, describe_symbol_type, describe_e_type, describe_e_version_numeric, describe_e_machine, describe_ei_osabi, describe_ei_version, describe_ei_data, describe_ei_class
# from elftools.elf.dynamic import DynamicSection
# from io import BytesIO, open
import re
import json


# In[342]:


class JsonParserStatic:
    def __init__(self):
        pass
    def parseFileType(self,file_type):
        file_type_dict = {}
        file_attr = file_type.split(",")
        file_type_dict["executable_type"] = file_attr[0]
        file_type_dict["architectuire_type"] = file_attr[1][1:]
        file_type_dict["compiler_interface"] = file_attr[2][1:]
        file_type_dict["extraa_info"] = file_attr[3:]
        return file_type_dict
    def parseFileExtension(self,ext):
        file_ext_dict = {}
        file_ext_dict["file_extension"] = ext
        return file_ext_dict
    def parseFileSize(self,size):
        file_size_dict = {}
        file_size_dict["file_size"] = size
        return file_size_dict
    def parseMd5Sum(self,md5_hash):
        file_hash_dict = {}
        file_hash_dict["file_md5_hash"] = md5_hash
        return file_hash_dict
    def parseFuzzyHash(self,ssdeep_hash):
        file_fuzzy_hash_dict = {}
        file_fuzzy_hash_dict["file_fuzzy_hash"] = ssdeep_hash
        return file_fuzzy_hash_dict
    def parseFuzzyHashMatching(self,fuzzy_match):
        file_fuzzy_hash_matching_dict = {}
        file_fuzzy_hash_matching_dict["fuzzy_matches"] = fuzzy_match
        return file_fuzzy_hash_matching_dict
    def parseStrings(self, ascii_strings, unicode_strings):
        file_strings_dict = {}
        #file_strings_dict["Strings"] = {}
        file_strings_dict["ascii_strings"] = ascii_strings.split("\n")
        unc_strings = unicode_strings.split("\n")
        if len(unc_strings) == 0:
            file_strings_dict["unicode_strings"] = "None"
        file_strings_dict["unicode_strings"] = unc_strings
        return file_strings_dict
    def parseYara(self, yara_packers, yara_capabilities):
        file_yara_dict = {}
        #file_yara_dict["yara_matching"] = {}
        if yara_packers == "[]":
            yara_packers = "None"
        if yara_capabilities == "[]":
            yara_capabilities = "None"
        file_yara_dict["yara_packers"] = yara_packers
        file_yara_dict["yara_capabilities"] = yara_capabilities
        return file_yara_dict
    def parseElfLinkedDepend(self,linkd_depnd):
        file_lnkd_depend = {}
        if linkd_depnd == "":
            file_lnkd_depend = None
        num_dpnd = 0
        if linkd_depnd == "ELF WITH NO LINKED DEPENDENCIES":
            file_lnkd_depend = "None"
        else:
            file_lnkd_depend = {}
            list_linkd_depnd = linkd_depnd.split("\n\t")
            list_linkd_depnd[0] = list_linkd_depnd[0][1:]
            list_linkd_depnd[len(list_linkd_depnd)-1] = list_linkd_depnd[len(list_linkd_depnd)-1][:-1]
            for dpnd in list_linkd_depnd:
                num_dpnd = num_dpnd + 1
                file_lnkd_depend[num_dpnd] = {}
                list_dpnd = dpnd.split(" ")
                if len(list_dpnd) == 2:
                    file_lnkd_depend[num_dpnd]["dependency_name"] = list_dpnd[0]
                    file_lnkd_depend[num_dpnd]["memory_address"] = list_dpnd[1][1:-1]
                else:
                    file_lnkd_depend[num_dpnd]["dependency_name"] = list_dpnd[0]
                    file_lnkd_depend[num_dpnd]["dependency_path"] = list_dpnd[2]
                    file_lnkd_depend[num_dpnd]["memory_address"] = list_dpnd[3][1:-1]
        return file_lnkd_depend
    def parseElfProgramHeader(self,elf_info):
        elf_data = {}
        if elf_info == "ELF with NO PROGRAM HEADER" or elf_info == "":
            elf_data["program_header"] = None
            return elf_data
        elf_info = [line.strip() for line in elf_info.split("\n") if line.strip()]
        elf_file_type_line = next((line for line in elf_info if line.startswith("Elf file type is")), None)
        if elf_file_type_line is not None:
            elf_data["Elf file type"] = elf_file_type_line.split("Elf file type is")[1].strip()

        entry_point_line = next((line for line in elf_info if line.startswith("Entry point")), None)
        if entry_point_line is not None:
            elf_data["Entry point"] = entry_point_line.split("Entry point")[1].strip()

        num_program_headers_line = next((line for line in elf_info if line.startswith("There are")), None)
        if num_program_headers_line is not None:
            num_program_headers = num_program_headers_line.split("There are")[1].split()[0]
            elf_data["Total program headers"] = int(num_program_headers)
        starting_offset_line = next((line for line in elf_info if line.startswith("There are")), None)
        if starting_offset_line is not None:
            starting_offset = re.findall(r'offset (\d+)', starting_offset_line)[0]
            elf_data["Starting offset"] = int(starting_offset)
        program_headers_start = next((i for i, line in enumerate(elf_info) if line == "Program Headers:"), None)
        if program_headers_start is not None:
            program_headers_info = elf_info[program_headers_start + 1:]

            headers_labels = program_headers_info[0].split()
            program_headers = []
            for line in program_headers_info[1:]:
                headers_data = line.split()
                if len(headers_data) == len(headers_labels):
                    program_header = {}
                    for i in range(len(headers_labels)):
                        program_header[headers_labels[i]] = headers_data[i]
                    program_headers.append(program_header)

            elf_data["Program Headers"] = program_headers
            section_segment_start = next((i for i, line in enumerate(elf_info) if line.startswith("Section to Segment mapping:")), None)
            if section_segment_start is not None:
                section_segment_info = elf_info[section_segment_start + 2:]

                segment_mapping = []
                for line in section_segment_info:
                    if line.strip() == "":
                        continue
                    segments = line.split()
                    segment_mapping.append(segments)

                elf_data["Section to Segment mapping"] = segment_mapping
        return elf_data
    def parseElfHeader(self,header_info_string):
        elf_header = {}
        if header_info_string == "ELF with NO HEADER" or header_info_string == "":
            elf_header = None
            return elf_header
    
        header_info = header_info_string.split("\n")

        elf_header["Magic Number"] = header_info[1].split(':')[1].strip()
        elf_header["Class"] = header_info[2].split(':')[1].strip()
        elf_header["Data"] = header_info[3].split(':')[1].strip()
        elf_header["Version"] = header_info[4].split(':')[1].strip()
        elf_header["OS/ABI"] = header_info[5].split(':')[1].strip()
        elf_header["ABI Version"] = header_info[6].split(':')[1].strip()
        elf_header["Type"] = header_info[7].split(':')[1].strip()
        elf_header["System Architecture"] = header_info[8].split(':')[1].strip()
        elf_header["Version"] = header_info[9].split(':')[1].strip()
        elf_header["Entry point address"] = header_info[10].split(':')[1].strip()
        elf_header["Start of program headers"] = int(re.findall(r'\d+', header_info[11])[0])
        elf_header["Start of section headers"] = int(re.findall(r'\d+', header_info[12])[0])
        elf_header["Flags"] = header_info[13].split(':')[1].strip()
        elf_header["Size of this header"] = int(re.findall(r'\d+', header_info[14])[0])
        elf_header["Size of program headers"] = int(re.findall(r'\d+', header_info[15])[0])
        elf_header["Number of program headers"] = int(re.findall(r'\d+', header_info[16])[0])
        elf_header["Size of section headers"] = int(re.findall(r'\d+', header_info[17])[0])
        elf_header["Number of section headers"] = int(re.findall(r'\d+', header_info[18])[0])
        elf_header["Section header string table index"] = int(re.findall(r'\d+', header_info[19])[0])

        return elf_header
    def parseCoreNotes(self,notes):
        result = {}
        if notes == "" or notes == "ELF with NO CORE NOTES":
            result["Core Notes"] = None
            return result
        lines = notes.strip().split('\n')

        line = 0
        while line < len(lines):
            section_name = lines[line].split(':')[1].strip()
            line += 2  # Skip the line with column headers
            notes = {}
            while line < len(lines) and lines[line].strip():
                columns = lines[line].split()
                if columns[0] == "OS:":
                    OS = columns[1]
                    ABI = columns[3]
                    notes[line] = {"OS":OS, "ABI":ABI}
                    line = line + 1
                    continue
                owner = columns[0]
                data_size = columns[1]
                description = ' '.join(columns[2:])
                notes[line] = {'Owner': owner, 'Data size': data_size, 'Description': description}
                line += 1
            result[section_name] = notes
            line += 1
        return result
    def parseSymbolTable(self,sym_table):
        symbol_tables = {}
        if sym_table == "\nDynamic symbol information is not available for displaying symbols.\n" or sym_table == "" or sym_table == "ELF with NO SYMBOL TABLE":
            return "None"
        
        current_table = None

        lines = sym_table.strip().split("\n")
        first = True
        for line in lines:
            if line.startswith("Symbol table"):
                table_name = line.split("'")[1]
                current_table = {}
                symbol_tables[table_name] = current_table
            elif current_table is not None and ":" in line:
                if first == True:
                    first = False
                    continue
                parts = line.strip().split(":")
                sym_tab = parts[1].split()
                entry = {}

                entry["Value"] = sym_tab[0].strip()
                entry["Size"] = (sym_tab[1].strip())
                entry["Type"] = sym_tab[2].strip()
                entry["Bind"] = sym_tab[3].strip()
                entry["Vis"] = sym_tab[4].strip()
                entry["Ndx"] = sym_tab[5].strip()
                if len(sym_tab) > 6:
                    entry["Name"] = sym_tab[6].strip()
                entry["Name"] = None        

                current_table[parts[0].strip()] = entry
        return symbol_tables
    def parseRelocationSection(self,rel_data):
        relocation_dict = {}
        if rel_data == "ELF with NO RELOCATION SECTION" or rel_data == "" or rel_data == "\nThere are no relocations in this file.\n":
            return "None"

        num_rel = 0
        sections = re.split(r'Relocation section ', rel_data)
        for section in sections[1:]:
            section_lines = section.strip().split('\n')
            section_name = section_lines[0].split("'")[1]
            relocation_entries = {}
            for line in section_lines[2:]:
                offset, info, typ, sym_value, sym_name = re.split(r'\s+', line.strip())
                num_rel = num_rel + 1
                entry = {
                    'Offset': offset,
                    'Info': info,
                    'Type': typ,
                    'Sym.Value': sym_value,
                    'Sym.Name': sym_name
                }
                relocation_entries[num_rel] = (entry)
            relocation_dict[section_name] = relocation_entries

        return relocation_dict



    
    
    
        


# In[343]:


# j = JsonParserStatic()


# In[344]:


# import subprocess
# o = subprocess.run(["readelf","-s","/home/ashutoshreddy/malwares/VirusShare_7ac8b664b91be7ad5ce88e7436cc2498"],stdout=subprocess.PIPE,check=True)
# st = (o.stdout)
# print(st)


# In[345]:


# import re

# data = st

# relocation_dict = {}

# num_rel = 0
# sections = re.split(r'Relocation section ', data)
# for section in sections[1:]:
#     section_lines = section.strip().split('\n')
#     section_name = section_lines[0].split("'")[1]
#     relocation_entries = {}
#     for line in section_lines[2:]:
#         offset, info, typ, sym_value, sym_name = re.split(r'\s+', line.strip())
#         num_rel = num_rel + 1
#         entry = {
#             'Offset': offset,
#             'Info': info,
#             'Type': typ,
#             'Sym.Value': sym_value,
#             'Sym.Name': sym_name
#         }
#         relocation_entries[num_rel] = (entry)
#     relocation_dict[section_name] = relocation_entries

# print(relocation_dict)


# In[346]:


# d = j.parseRelocationSection(st)
# print(d)


# In[347]:


# data =  st 

# symbol_tables = {}
# current_table = None

# lines = data.strip().split("\n")
# first = True
# for line in lines:
#     #print(line)

#     if line.startswith("Symbol table"):
#         table_name = line.split("'")[1]
#         current_table = {}
#         symbol_tables[table_name] = current_table
#     elif current_table is not None and ":" in line:
#         if first == True:
#             first = False
#             continue
#         parts = line.strip().split(":")
#         #print(parts)
#         sym_tab = parts[1].split()
#         #print(sym_tab)
# #         print(parts)
#         entry = {}
    
#         entry["Value"] = sym_tab[0].strip()
#         entry["Size"] = (sym_tab[1].strip())
#         entry["Type"] = sym_tab[2].strip()
#         entry["Bind"] = sym_tab[3].strip()
#         entry["Vis"] = sym_tab[4].strip()
#         entry["Ndx"] = sym_tab[5].strip()
#         if len(sym_tab) > 6:
#             entry["Name"] = sym_tab[6].strip()
#         entry["Name"] = None        
        
#         current_table[parts[0].strip()] = entry

# print(symbol_tables)


# In[348]:


# data = st

# result = {}
# lines = data.strip().split('\n')

# line = 0
# while line < len(lines):
#     section_name = lines[line].split(':')[1].strip()
#     line += 2  # Skip the line with column headers
#     notes = {}
#     while line < len(lines) and lines[line].strip():
#         columns = lines[line].split()
#         if columns[0] == "OS:":
#             OS = columns[1]
#             ABI = columns[3]
#             notes[line] = {"OS":OS, "ABI":ABI}
#             line = line + 1
#             continue
#         owner = columns[0]
#         data_size = columns[1]
#         description = ' '.join(columns[2:])
#         notes[line] = {'Owner': owner, 'Data size': data_size, 'Description': description}
#         line += 1
#     result[section_name] = notes
#     line += 1
# print(result)


# In[349]:


# import re

# def parse_elf_header(header_info):
#     elf_header = {}
    
#     elf_header["Magic Number"] = header_info[1].split(':')[1].strip()
#     elf_header["Class"] = header_info[2].split(':')[1].strip()
#     elf_header["Data"] = header_info[3].split(':')[1].strip()
#     elf_header["Version"] = header_info[4].split(':')[1].strip()
#     elf_header["OS/ABI"] = header_info[5].split(':')[1].strip()
#     elf_header["ABI Version"] = header_info[6].split(':')[1].strip()
#     elf_header["Type"] = header_info[7].split(':')[1].strip()
#     elf_header["System Architecture"] = header_info[8].split(':')[1].strip()
#     elf_header["Version"] = header_info[9].split(':')[1].strip()
#     elf_header["Entry point address"] = header_info[10].split(':')[1].strip()
#     elf_header["Start of program headers"] = int(re.findall(r'\d+', header_info[11])[0])
#     elf_header["Start of section headers"] = int(re.findall(r'\d+', header_info[12])[0])
#     elf_header["Flags"] = header_info[13].split(':')[1].strip()
#     elf_header["Size of this header"] = int(re.findall(r'\d+', header_info[14])[0])
#     elf_header["Size of program headers"] = int(re.findall(r'\d+', header_info[15])[0])
#     elf_header["Number of program headers"] = int(re.findall(r'\d+', header_info[16])[0])
#     elf_header["Size of section headers"] = int(re.findall(r'\d+', header_info[17])[0])
#     elf_header["Number of section headers"] = int(re.findall(r'\d+', header_info[18])[0])
#     elf_header["Section header string table index"] = int(re.findall(r'\d+', header_info[19])[0])
    
#     return elf_header

# # Sample ELF header information for testing
# header_info = [
#     "	ELF Header:",
#     "  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 ",
#     "  Class:                             ELF32",
#     "  Data:                              2's complement, little endian",
#     "  Version:                           1 (current)",
#     "  OS/ABI:                            UNIX - System V",
#     "  ABI Version:                       0",
#     "  Type:                              EXEC (Executable file)",
#     "  Machine:                           Intel 80386",
#     "  Version:                           0x1",
#     "  Entry point address:               0x8049230",
#     "  Start of program headers:          52 (bytes into file)",
#     "  Start of section headers:          42760 (bytes into file)",
#     "  Flags:                             0x0",
#     "  Size of this header:               52 (bytes)",
#     "  Size of program headers:           32 (bytes)",
#     "  Number of program headers:         6",
#     "  Size of section headers:           40 (bytes)",
#     "  Number of section headers:         27",
#     "  Section header string table index: 24"
# ]

# elf_header = parse_elf_header(header_info)
# print(elf_header)


# In[350]:


# d=j.parseElfHeader(st)
# print(d)


# In[351]:


# d = parse_elf_info(st)


# In[352]:


# import json
# import re

# def parse_elf_info(elf_info):
#     elf_data = {}
#     elf_file_type_line = next((line for line in elf_info if line.startswith("Elf file type is")), None)
#     if elf_file_type_line is not None:
#         elf_data["Elf file type"] = elf_file_type_line.split("Elf file type is")[1].strip()

#     entry_point_line = next((line for line in elf_info if line.startswith("Entry point")), None)
#     if entry_point_line is not None:
#         elf_data["Entry point"] = entry_point_line.split("Entry point")[1].strip()

#     num_program_headers_line = next((line for line in elf_info if line.startswith("There are")), None)
#     if num_program_headers_line is not None:
#         num_program_headers = num_program_headers_line.split("There are")[1].split()[0]
#         elf_data["Total program headers"] = int(num_program_headers)
#     starting_offset_line = next((line for line in elf_info if line.startswith("There are")), None)
#     if starting_offset_line is not None:
#         starting_offset = re.findall(r'offset (\d+)', starting_offset_line)[0]
#         elf_data["Starting offset"] = int(starting_offset)
#     program_headers_start = next((i for i, line in enumerate(elf_info) if line == "Program Headers:"), None)
#     if program_headers_start is not None:
#         program_headers_info = elf_info[program_headers_start + 1:]
        
#         headers_labels = program_headers_info[0].split()
#         program_headers = []
#         for line in program_headers_info[1:]:
#             headers_data = line.split()
#             if len(headers_data) == len(headers_labels):
#                 program_header = {}
#                 for i in range(len(headers_labels)):
#                     program_header[headers_labels[i]] = headers_data[i]
#                 program_headers.append(program_header)
        
#         elf_data["Program Headers"] = program_headers
#         section_segment_start = next((i for i, line in enumerate(elf_info) if line.startswith("Section to Segment mapping:")), None)
#         if section_segment_start is not None:
#             section_segment_info = elf_info[section_segment_start + 2:]

#             segment_mapping = []
#             for line in section_segment_info:
#                 if line.strip() == "":
#                     continue
#                 segments = line.split()
#                 segment_mapping.append(segments)

#             elf_data["Section to Segment mapping"] = segment_mapping
#     return elf_data

# # Sample ELF information for testing
# elf_info = st
# # Split the input into lines and remove empty lines
# elf_info_lines = [line.strip() for line in elf_info.split("\n") if line.strip()]

# # Parse ELF information and convert to JSON
# parsed_data = parse_elf_info(elf_info_lines)
# json_data = json.dumps(parsed_data, indent=4)
# print(json_data)

