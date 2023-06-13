#!/usr/bin/env python
# coding: utf-8

# In[304]:


import os
import stat


# In[436]:


class FileOperations:
    def __init__(self, scap_file, only_syscall):
        self.file = scap_file
        self.only_syscall = only_syscall
        self.file_ops = ["open","openat","openat2","rename", "renameat", "renameat2", "mkdir", "mkdirat","rmdir", "unlink", "unlinkat","remove", "access", "readdir","opendir","closedir","truncate","ftruncate","read","write","link","linkat","open_by_handle_at","creat","lseek","llseek","pread64","pwrite","fchdir","symlink","symlinkat","mount", "umount","link","linkat","chmod" ,"fchmod", "fchmodat", "close"]
    def jsonParser(self):
        scap_dict = {}
        api_calls = {}
        file = open(self.file,"r")
        syscalls = (file.read()).split("\n")[:-2]
        num_write = 0
        num_lseek = 0
        num_ftruncate = 0
        num_chmod = 0
        for syscall in syscalls:
            scap_attr = syscall.split("  ")
            pid = scap_attr[0]
            if pid not in scap_dict.keys():
                scap_dict[pid]={}
            syscall_name = ""
            name_len = 0
            for letter in scap_attr[1]:
                if letter != "(":
                    syscall_name = syscall_name + letter
                    name_len = name_len + 1
                else:
                    break
            syscall_attr = (scap_attr[1])[name_len:]
            symbol_list = ["!","@","#","$","%","*","(",")","+","-","_","=",".",">","<",",",":",";","~","`"]
            syscall_name = syscall_name.strip()
            if syscall_name not in api_calls.keys():
                if syscall_name[0] not in symbol_list:
                    api_calls[syscall_name] = 1
            else:
                if syscall_name[0] not in symbol_list:
                    api_calls[syscall_name] = api_calls[syscall_name] + 1
            if self.only_syscall:
                continue
            if syscall_name not in self.file_ops:
                continue
            else:
                if syscall_name not in scap_dict[pid].keys():
                    scap_dict[pid][syscall_name] = {}
                if syscall_name == "access":
                    if "filename_and_access_type" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["filename_and_access_type"] = []
                    filename_and_access_type = ""
                    for letter in syscall_attr:
                        if letter != ")":
                            filename_and_access_type = filename_and_access_type + letter
                        else:
                            break
                    filename_and_access_type = filename_and_access_type + ")"
                    if filename_and_access_type not in scap_dict[pid][syscall_name]["filename_and_access_type"]:
                        scap_dict[pid][syscall_name]["filename_and_access_type"].append(filename_and_access_type)
                elif syscall_name == "openat":
                    if "filename_with_path" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["filename_with_path"] = {}
                    return_FD = syscall_attr[-1]
                    syscall_attr = syscall_attr[1:-5]
                    list_syscall_attr = syscall_attr.split(",")
                    filename_with_path = list_syscall_attr[1]
                    if filename_with_path not in scap_dict[pid][syscall_name]["filename_with_path"].keys():
                        scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path] = {}
                    if "openat_descriptor" not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path].keys():
                        scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["openat_descriptor"] = []
                    openat_descriptor = list_syscall_attr[0]
                    if openat_descriptor not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["openat_descriptor"]:
                        scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["openat_descriptor"].append(openat_descriptor)
                    if "flags" not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path].keys():
                        scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["flags"] = []
                    flags = list_syscall_attr[2]
                    if flags not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["flags"]:
                        scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["flags"].append(flags)
                    if "return_FD" not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path].keys():
                        scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"] = []
                    if return_FD not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"]:
                        if return_FD == ")":
                            scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"].append("None")
                        else:
                            scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"].append(return_FD)
                elif syscall_name == "close":
                    if "file_descriptor_of_closing_file" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["file_descriptor_of_closing_file"] = []
                    fd = syscall_attr[1]
                    scap_dict[pid][syscall_name]["file_descriptor_of_closing_file"].append(fd)
                elif syscall_name == "read":
                    if "file_descriptor" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["file_descriptor"] = []
                    if "read_buffer_values" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["read_buffer_values"] = []
                    list_syscall_attr = syscall_attr.split(",")
                    fd = list_syscall_attr[0][1:]
                    read_buffer_values = list_syscall_attr[1]
                    scap_dict[pid][syscall_name]["file_descriptor"].append(fd)
                    if read_buffer_values not in scap_dict[pid][syscall_name]["read_buffer_values"]:
                        scap_dict[pid][syscall_name]["read_buffer_values"].append(read_buffer_values)
                elif syscall_name == "readdir":
                    list_dir_attr = syscall_attr.split("{")
                    dir_attr = ""
                    dir_name = "None"
                    if len(list_dir_attr) > 1:
                        dir_attr = (list_dir_attr[1]).split("}")[0]
                    else:
                        dir_name = syscall_attr.split(",")[1]
                    dir_var = (dir_attr[1:-1]).split(",")
                    dir_inode = "None"
                    dir_offset = "None"
                    dir_entry_len = "None"
                    if len(dir_var) > 1 :
                        dir_name = ((dir_var[3]).split("="))[1][1:]
                        dir_inode = ((dir_var[0]).split("="))[1]
                        dir_offset = ((dir_var[1]).split("="))[1]
                        dir_entry_len = ((dir_var[2]).split("="))[1]
                    file_descriptor = (syscall_attr.split(","))[0][1:]
                    if "dir_name" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["dir_name"] = {}
                    if dir_name not in scap_dict[pid][syscall_name]["dir_name"].keys():
                        scap_dict[pid][syscall_name]["dir_name"][dir_name] = {}
                    if "dir_offset" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_offset"] = []
                    if dir_offset not in scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_offset"]:
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_offset"].append(dir_offset)
                    if "dir_inode" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_inode"] = []
                    if dir_inode not in scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_inode"]:
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_inode"].append(dir_inode)
                    if "dir_entry_len" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_entry_len"] = []
                    if dir_entry_len not in scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_entry_len"]:
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_entry_len"].append(dir_entry_len)
                    if "file_descriptor" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
                        scap_dict[pid][syscall_name]["dir_name"][dir_name]["file_descriptor"] = []
                    scap_dict[pid][syscall_name]["dir_name"][dir_name]["file_descriptor"].append(file_descriptor)
                elif syscall_name == "open":
                    syscall_vars = syscall_attr.split(",")
                    #print(syscall_vars)
                    if "dir_name/file_name" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["dir_name/file_name"] = {}
                    dir_name = syscall_vars[0][2:-1]
                    flags = syscall_vars[1][1:-1]
                    if dir_name not in scap_dict[pid][syscall_name]["dir_name/file_name"].keys():
                        scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name] = {}
                    if "flags" not in scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name].keys():
                        scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name]["flags"] = []
                    if flags not in scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name]["flags"]:
                        scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name]["flags"].append(flags)
                elif syscall_name == "write":
                    num_write = num_write + 1
                    syscall_vars = syscall_attr.split(",")
                    scap_dict[pid][syscall_name][num_write] = {}
                    file_descriptor = (syscall_vars[0])[1:]
                    data = (syscall_vars[1])[1:-1]
                    data_size = "None"
                    if len(syscall_vars) > 2:
                        data_size = (syscall_vars[len(syscall_vars)-1]).split(")")[0][1:]
                    scap_dict[pid][syscall_name][num_write]["file_descriptor"] = file_descriptor
                    scap_dict[pid][syscall_name][num_write]["data"] = data
                    scap_dict[pid][syscall_name][num_write]["data_size"] = data_size
                elif syscall_name == "lseek":
                    num_lseek = num_lseek + 1
                    syscall_vars = syscall_attr.split(",")
                    scap_dict[pid][syscall_name][num_lseek] = {}
                    file_descriptor = (syscall_vars[0])[1:]
                    lseek_offset = (syscall_vars[1])[1:]
                    lseek_whence = (syscall_vars[2])[1:-1]
                    scap_dict[pid][syscall_name][num_lseek]["file_descriptor"] = file_descriptor
                    scap_dict[pid][syscall_name][num_lseek]["lseek_offset"] = lseek_offset
                    scap_dict[pid][syscall_name][num_lseek]["lseek_whence"] = lseek_whence
                elif syscall_name == "unlink":
                    file_name = syscall_attr[1:-1]
                    if "file_name" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["file_name"] = []
                    if file_name not in scap_dict[pid][syscall_name]["file_name"]:
                        scap_dict[pid][syscall_name]["file_name"].append(file_name)
                elif syscall_name == "ftruncate":
                    num_ftruncate = num_ftruncate + 1
                    syscall_vars = syscall_attr.split(",")
                    scap_dict[pid][syscall_name][num_ftruncate] = {}
                    file_descriptor = syscall_vars[0][1:]
                    truncate_size = syscall_vars[1][1:-1]
                    scap_dict[pid][syscall_name][num_ftruncate]["file_descriptor"] = file_descriptor
                    scap_dict[pid][syscall_name][num_ftruncate]["truncate_size"] = truncate_size
                elif syscall_name == "chmod":
                    num_chmod = num_chmod + 1
                    scap_dict[pid][syscall_name][num_chmod] = {}
                    syscall_vars = syscall_attr.split(",")
                    file_name = syscall_vars[0][2:-1]
                    permission = syscall_vars[1][1:-5]
                    permission = stat.filemode(int(permission, 8))
                    scap_dict[pid][syscall_name][num_chmod]["file_name"] = file_name
                    scap_dict[pid][syscall_name][num_chmod]["permission"] = permission
                elif syscall_name == "pread64":
                    if "file_descriptor" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["file_descriptor"] = []
                    if "read_buffer_values" not in scap_dict[pid][syscall_name].keys():
                        scap_dict[pid][syscall_name]["read_buffer_values"] = []
                    list_syscall_attr = syscall_attr.split(",")
                    fd = list_syscall_attr[0][1:]
                    read_buffer_values = list_syscall_attr[1]
                    scap_dict[pid][syscall_name]["file_descriptor"].append(fd)
                    if read_buffer_values not in scap_dict[pid][syscall_name]["read_buffer_values"]:
                        scap_dict[pid][syscall_name]["read_buffer_values"].append(read_buffer_values)
                    
        temp_scap_dict = { key:(None if scap_dict[key]=={} else scap_dict[key]) for key in scap_dict}
        scap_dict = temp_scap_dict
        return [scap_dict, api_calls]
    
                






                    
                
                
                
            
            
            
            
        
        
        
        
        


# In[428]:


# file="/home/ashutoshreddy/sandbox_reports/VirusShare_e049498725a4c8cb66db8bcd2f26ba08/dynamic_analysis/sample_strace_out.txt"
# f=open(file,"r")


# In[437]:


# file_ops = ["open","openat","openat2","rename", "renameat", "renameat2", "mkdir", "mkdirat","rmdir", "unlink", "unlinkat","remove", "access", "readdir","opendir","closedir","truncate","ftruncate","read","write","link","linkat","open_by_handle_at","creat","lseek","llseek","pread64","pwrite","fchdir","symlink","symlinkat","mount", "umount","link","linkat","chmod" ,"fchmod", "fchmodat", "close"]
# val=f.read()


# In[438]:


# len(file_ops)


# In[439]:


# def octal_to_rwx(octal):
#     # Convert octal to decimal
#     decimal = int(octal, 8)

#     # Get the permission string in rwxr-xr-x format
#     permission = stat.filemode(decimal)

#     return permission
# octal_to_rwx('7')


# In[435]:


# vals=val.split("\n")[:-2]
# scap_dict = {}
# num_write = 0
# num_lseek = 0
# num_ftruncate = 0
# num_chmod = 0
# for v in vals:
#     v_attr = v.split("  ")
#     pid=v_attr[0]
#     if pid not in scap_dict.keys():
#         scap_dict[pid] = {}
#     syscall_name=""
#     name_len = 0
#     for letter in v_attr[1]:
#         if letter != "(":
#             syscall_name = syscall_name + letter
#             name_len = name_len + 1
#         else:
#             break
#     syscall_attr = (v_attr[1])[name_len:]
#     if syscall_name not in file_ops:
#         continue
#     else:
#         if syscall_name not in scap_dict[pid].keys():
#             scap_dict[pid][syscall_name] = {}
#         if syscall_name == "access":
#             if "filename_and_access_type" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["filename_and_access_type"] = []
#             filename_and_access_type = ""
#             for letter in syscall_attr:
#                 if letter != ")":
#                     filename_and_access_type = filename_and_access_type + letter
#                 else:
#                     break
#             filename_and_access_type = filename_and_access_type + ")"
#             if filename_and_access_type not in scap_dict[pid][syscall_name]["filename_and_access_type"]: 
#                 scap_dict[pid][syscall_name]["filename_and_access_type"].append(filename_and_access_type)
#         elif syscall_name == "openat":
#             if "filename_with_path" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["filename_with_path"] = {}
#             return_FD = syscall_attr[-1]
#             syscall_attr = syscall_attr[1:-5]
#             list_syscall_attr = syscall_attr.split(",")
#             filename_with_path = list_syscall_attr[1]
#             if filename_with_path not in scap_dict[pid][syscall_name]["filename_with_path"].keys():
#                 scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path] = {}
#             if "openat_descriptor" not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path].keys():
#                 scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["openat_descriptor"] = []
#             openat_descriptor = list_syscall_attr[0]
#             if openat_descriptor not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["openat_descriptor"]:
#                 scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["openat_descriptor"].append(openat_descriptor)
#             if "flags" not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path].keys():
#                 scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["flags"] = []
#             flags = list_syscall_attr[2]
#             if flags not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["flags"]:
#                 scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["flags"].append(flags)
#             if "return_FD" not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path].keys():
#                 scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"] = []
#             if return_FD not in scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"]:
#                 if return_FD == ")":
#                     scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"].append("None")
#                 else:
#                     scap_dict[pid][syscall_name]["filename_with_path"][filename_with_path]["return_FD"].append(return_FD)
#         elif syscall_name == "close":
#             if "file_descriptor_of_closing_file" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["file_descriptor_of_closing_file"] = []
#             fd = syscall_attr[1]
#             scap_dict[pid][syscall_name]["file_descriptor_of_closing_file"].append(fd)
#         elif syscall_name == "read":
#             if "file_descriptor" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["file_descriptor"] = []
#             if "read_buffer_values" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["read_buffer_values"] = []
#             list_syscall_attr = syscall_attr.split(",")
#             fd = list_syscall_attr[0][1:]
#             read_buffer_values = list_syscall_attr[1]
#             scap_dict[pid][syscall_name]["file_descriptor"].append(fd)
#             if read_buffer_values not in scap_dict[pid][syscall_name]["read_buffer_values"]:
#                 scap_dict[pid][syscall_name]["read_buffer_values"].append(read_buffer_values)
#         elif syscall_name == "pread64":
#             if "file_descriptor" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["file_descriptor"] = []
#             if "read_buffer_values" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["read_buffer_values"] = []
#             list_syscall_attr = syscall_attr.split(",")
#             fd = list_syscall_attr[0][1:]
#             read_buffer_values = list_syscall_attr[1]
#             scap_dict[pid][syscall_name]["file_descriptor"].append(fd)
#             if read_buffer_values not in scap_dict[pid][syscall_name]["read_buffer_values"]:
#                 scap_dict[pid][syscall_name]["read_buffer_values"].append(read_buffer_values)
#         elif syscall_name == "readdir":
#             list_dir_attr = syscall_attr.split("{")
#             dir_attr = ""
#             dir_name = "None"
#             if len(list_dir_attr) > 1:
#                 dir_attr = (list_dir_attr[1]).split("}")[0]
#             else:
#                 dir_name = syscall_attr.split(",")[1]
#             dir_var = (dir_attr[1:-1]).split(",")
#             dir_inode = "None"
#             dir_offset = "None"
#             dir_entry_len = "None"
#             if len(dir_var) > 1 :
#                 dir_name = ((dir_var[3]).split("="))[1][1:]
#                 dir_inode = ((dir_var[0]).split("="))[1]
#                 dir_offset = ((dir_var[1]).split("="))[1]
#                 dir_entry_len = ((dir_var[2]).split("="))[1]
#             file_descriptor = (syscall_attr.split(","))[0][1:]
#             if "dir_name" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name"] = {}
#             if dir_name not in scap_dict[pid][syscall_name]["dir_name"].keys():
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name] = {}
#             if "dir_offset" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_offset"] = []
#             if dir_offset not in scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_offset"]:
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_offset"].append(dir_offset)
#             if "dir_inode" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_inode"] = []
#             if dir_inode not in scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_inode"]:
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_inode"].append(dir_inode)
#             if "dir_entry_len" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_entry_len"] = []
#             if dir_entry_len not in scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_entry_len"]:
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["dir_entry_len"].append(dir_entry_len)
#             if "file_descriptor" not in scap_dict[pid][syscall_name]["dir_name"][dir_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name"][dir_name]["file_descriptor"] = []
#             scap_dict[pid][syscall_name]["dir_name"][dir_name]["file_descriptor"].append(file_descriptor)
#         elif syscall_name == "open":
#             syscall_vars = syscall_attr.split(",")
#             #print(syscall_vars)
#             if "dir_name/file_name" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name/file_name"] = {}
#             dir_name = syscall_vars[0][2:-1]
#             flags = syscall_vars[1][1:-1]
#             if dir_name not in scap_dict[pid][syscall_name]["dir_name/file_name"].keys():
#                 scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name] = {}
#             if "flags" not in scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name].keys():
#                 scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name]["flags"] = []
#             if flags not in scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name]["flags"]:
#                 scap_dict[pid][syscall_name]["dir_name/file_name"][dir_name]["flags"].append(flags)
#         elif syscall_name == "write":
#             num_write = num_write + 1
#             syscall_vars = syscall_attr.split(",")
#             scap_dict[pid][syscall_name][num_write] = {}
#             file_descriptor = (syscall_vars[0])[1:]
#             data = (syscall_vars[1])[1:-1]
#             data_size = "None"
#             if len(syscall_vars) > 2:
#                 data_size = (syscall_vars[len(syscall_vars)-1]).split(")")[0][1:]
#             scap_dict[pid][syscall_name][num_write]["file_descriptor"] = file_descriptor
#             scap_dict[pid][syscall_name][num_write]["data"] = data
#             scap_dict[pid][syscall_name][num_write]["data_size"] = data_size
#         elif syscall_name == "lseek":
#             num_lseek = num_lseek + 1
#             syscall_vars = syscall_attr.split(",")
#             scap_dict[pid][syscall_name][num_lseek] = {}
#             file_descriptor = (syscall_vars[0])[1:]
#             lseek_offset = (syscall_vars[1])[1:]
#             lseek_whence = (syscall_vars[2])[1:-1]
#             scap_dict[pid][syscall_name][num_lseek]["file_descriptor"] = file_descriptor
#             scap_dict[pid][syscall_name][num_lseek]["lseek_offset"] = lseek_offset
#             scap_dict[pid][syscall_name][num_lseek]["lseek_whence"] = lseek_whence
#         elif syscall_name == "unlink":
#             file_name = syscall_attr[1:-1]
#             if "file_name" not in scap_dict[pid][syscall_name].keys():
#                 scap_dict[pid][syscall_name]["file_name"] = []
#             if file_name not in scap_dict[pid][syscall_name]["file_name"]:
#                 scap_dict[pid][syscall_name]["file_name"].append(file_name)
#         elif syscall_name == "ftruncate":
#             num_ftruncate = num_ftruncate + 1
#             syscall_vars = syscall_attr.split(",")
#             scap_dict[pid][syscall_name][num_ftruncate] = {}
#             file_descriptor = syscall_vars[0][1:]
#             truncate_size = syscall_vars[1][1:-1]
#             scap_dict[pid][syscall_name][num_ftruncate]["file_descriptor"] = file_descriptor
#             scap_dict[pid][syscall_name][num_ftruncate]["truncate_size"] = truncate_size
#         elif syscall_name == "chmod":
#             num_chmod = num_chmod + 1
#             scap_dict[pid][syscall_name][num_chmod] = {}
#             syscall_vars = syscall_attr.split(",")
#             file_name = syscall_vars[0][2:-1]
#             permission = syscall_vars[1][1:-5]
#             permission = stat.filemode(int(permission, 8))
#             scap_dict[pid][syscall_name][num_chmod]["file_name"] = file_name
#             scap_dict[pid][syscall_name][num_chmod]["permission"] = permission
#         temp_scap_dict = { key:(None if scap_dict[key]=={} else scap_dict[key]) for key in scap_dict}
#         scap_dict = temp_scap_dict
#         print(scap_dict)
        
            
            
            
            

            
            
                
            
            
            
            
            
            
            
                
            
            
        
            
            
    
    


# In[440]:


# vals


# In[441]:


# scap_dict


# In[442]:


# sd2 = scap_dict
# sd2['1234']={'a':'A'}


# In[443]:


# sd2.keys()


# In[444]:


# sd = { k:(None if sd2[k]=={} else sd2[k]) for k in sd2}


# In[445]:


# sd

