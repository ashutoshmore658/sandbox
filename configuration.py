#!/usr/bin/env python
# coding: utf-8

# In[2]:


py_path=r"/usr/bin/python3.10"
report_dir=r"/home/ashutoshreddy/sandbox_reports"
dash_lines = "-" * 40
yara_packer_rules=r"/home/ashutoshreddy/yara_rules/packer.yara"
yara_rules=r"/home/ashutoshreddy/yara_rules/capabilities.yara"
vm_id="vm"
analysis_username="root"
analysis_password="1234"
analysis_clean_snapname="vm_fresh_1"
analysis_mal_dir=r"/home/u/malware"
is_elf_file=False
virustotal_key = "***************Virustotal public api key*****************"


# In[ ]:


analysis_sysdig_path = r'/usr/bin/sysdig'
host_sysdig_path = r'/usr/bin/sysdig'
analysis_log_outpath = r'/home/u/log'
analysis_capture_out_file = analysis_log_outpath + "/sysdig_scap_out.scap"

cap_format = "%proc.name (%thread.tid) %evt.dir %evt.type %evt.args"
cap_filter = r"""evt.type=clone or evt.type=execve or evt.type=chdir or evt.type=open or
evt.type=creat or evt.type=close or evt.type=socket or evt.type=bind or evt.type=connect or
evt.type=accept or evt.is_io=true or evt.type=unlink or evt.type=rename or evt.type=brk or
evt.type=mmap or evt.type=munmap or evt.type=kill or evt.type=pipe"""

analysis_strace_path = r'/usr/bin/strace'
strace_filter = r"-etrace=fork,clone,execve,chdir,open,creat,close,socket,connect,accept,bind,read,write,unlink,rename,kill,pipe,dup,dup2"
analysis_strace_out_file = r'/home/u/log/sample_strace_out.txt'


params = []


# In[ ]:


analysis_ip = "192.168.56.101"
host_iface_to_sniff = "vboxnet0"
host_tcpdumppath = "/usr/sbin/tcpdump"


#memory variables

#vm_memory_profile = r"/home/ashutoshreddy/Memory_profile/vmlinux-5.15.0-72-generic.json"
mem_dump_dir = report_dir + "/" + "Memory_dumps"
voltility_path = r"/home/ashutoshreddy/volatility3/vol.py"
memory_dump_path = r"/home/ashutoshreddy/Memory_dumps/abc.vmem"
memory_profile_dir = r"/home/ashutoshreddy/Memory_profile/"

