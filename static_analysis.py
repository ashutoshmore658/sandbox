#!/usr/bin/env python
# coding: utf-8

# In[1]:


import yara
import json
import os
import subprocess
import sys
import requests


# In[2]:


class Static:
    def __init__(self,malware_file):
        self.file=malware_file
        self.md5_hash=""
    def fileType(self):
        if os.path.exists(self.file):
            o=subprocess.run(['file','-b',self.file],stdout=subprocess.PIPE,check=True)
            file_type=(o.stdout).decode()
            name=str('test.txt')
            ind_split=name.split(".")
            given_ext=ind_split[-1]
            code=o.returncode
            return [file_type,given_ext,code]
        else:
            print("No such file or directory : ",self.file)
            sys.exit()
    def fileSize(self):
        o=subprocess.run(['ls','-h','-l',self.file],stdout=subprocess.PIPE,check=True)
        file_size=(o.stdout).decode().split(" ")[4]
        code=o.returncode
        return [file_size,code]
    def md5Sum(self):
        if os.path.exists(self.file):
            o=subprocess.run(['md5sum',self.file],check=True,stdout=subprocess.PIPE)
            self.md5_hash=(o.stdout).decode().split(" ")[0]
            code=o.returncode
            return [self.md5_hash,code]
        else:
            print("No such file or directory : ",self.file)
            sys.exit()
    def ssdeep(self,master_ssdeep_file):
        o=subprocess.run(['ssdeep',self.file],stdout=subprocess.PIPE,check=True)
        std_output=o.stdout
        std_output=std_output.decode()
        fuzzy_hash=(std_output.split("\n")[1])
        code=o.returncode
        o=subprocess.run(['ssdeep','-b',self.file,'>',master_ssdeep_file],stdout=subprocess.PIPE,check=True)
        return [fuzzy_hash,code]
    def ssdeep_match(self, collected_fuzzyHashes):
        o=subprocess.run(['ssdeep','-bm',collected_fuzzyHashes,self.file],stdout=subprocess.PIPE,check=True)
        return (o.stdout).decode()
    def yaraRules(self, rulesfile):
        rules = yara.compile(rulesfile)
        matches = rules.match(self.file)
        return matches
    def asciiStrings(self):
        o=subprocess.run(['strings','-a',self.file],check=True,stdout=subprocess.PIPE)
        ascii_strings=(o.stdout).decode()
        return [ascii_strings,o.returncode]
    def unicodeStrings(self):
        o=subprocess.run(['strings','-a','-el',self.file],check=True,stdout=subprocess.PIPE)
        unicode_strings=(o.stdout).decode()
        return [unicode_strings,o.returncode]
    def linkedDependencies(self):
        try:
            o=subprocess.run(["ldd",self.file],stdout=subprocess.PIPE,check=True)
            linked_library=(o.stdout).decode()
            code=o.returncode
            return linked_library
        except:
            return "ELF WITH NO LINKED DEPENDENCIES"
    def elfHeader(self):
        try:
            o=subprocess.run(['readelf','-h',self.file],stdout=subprocess.PIPE,check=True)
            elf_header=(o.stdout).decode()
            return elf_header
        except:
            return "ELF with NO HEADER"
        
    def programHeader(self):
        try:
            o=subprocess.run(['readelf','-l',self.file],stdout=subprocess.PIPE,check=True)
            program_header=(o.stdout).decode()
            return program_header
        except:
            return "ELF with NO PROGRAM HEADER"
    def sectionsOFAddressSpace(self):
        try:
            o=subprocess.run(['readelf','-S',self.file],stdout=subprocess.PIPE,check=True)
            sections_oap=(o.stdout).decode()
            return sections_oap
        except:
            return "ELF with NO SECTION OF ADDRESS SPACE"
    def symbolTable(self):
        try:
            o=subprocess.run(['readelf','-s',self.file],stdout=subprocess.PIPE,check=True)
            symbol_table=(o.stdout).decode()
            return symbol_table
        except:
            return "ELF with NO SYMBOL TABLE"
    def relocationSection(self):
        try:
            o=subprocess.run(['readelf','-r',self.file],stdout=subprocess.PIPE,check=True)
            relocation_section=(o.stdout).decode()
            return relocation_section
        except:
            return "ELF with NO RELOCATION SECTION"
    def dynamicSection(self):
        try:
            o=subprocess.run(['readelf','-d',self.file],srdout=subprocess.PIPE,check=True)
            dynamic_section=(o.stdout).decode()
            return dynamic_section
        except:
            return "ELF with NO DYNAMIC SECTION"
    def coreNotes(self):
        try:
            o=subprocess.run(['readelf','-n',self.file],stdout=subprocess.PIPE,check=True)
            core_notes=(o.stdout).decode()
            return core_notes
        except:
            return "ELF with NO CORE NOTES"
    def virusTotal(self, publicapi_key):
        api_link='https://www.virustotal.com/vtapi/v2/file/report'
        md5=self.md5_hash
        params={'apikey':publicapi_key,'resource':md5}
        headers = {"Accept-Encoding": "gzip, deflate",
                       "User-Agent" : "gzip,  My Python requests library example client or username"}
        try:
            response = requests.get(api_link,params=params, headers=headers)
            response.raise_for_status()
            ana_dict=response.json()
            return ana_dict
#             if ana_dict['result']==0:
#                 print("        No Previous Record For : ", self.md5_hash)
#             else:
#                 analysis=ana_dict['report'][1]
#                 return analysis
        except requests.exceptions.HTTPError as errh:
            print ("Can NOT Fetch Results from VirusTotal-> Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
            print ("Can NOT Fetch Results from VirusTotal-> Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
            print ("Can NOT Fetch Results from VirusTotal-> Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
            print ("Can NOT Fetch Results from VirusTotal-> OOps: Something Else",err)
                


# In[ ]:




