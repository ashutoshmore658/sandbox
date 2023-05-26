#!/usr/bin/env python
# coding: utf-8

# In[1]:
import sys

# Handle import error for 'Mapping' in Python 3.10
if sys.version_info >= (3, 10):
    from collections.abc import Mapping
else:
    from collections import Mapping
from static_analysis import*
from VirtualBox import*
from configuration import*
from memory_analysis import*
import argparse
import shutil
import time
import os


# checking if filename and arguments are provided
if len(sys.argv) <= 1:
    print("Please give some options, type -h or --help for more information")
    sys.exit()

# adding and parsing  options
parser = argparse.ArgumentParser(description='Usage: %prog [Options] <file> [args]')
parser.add_argument("file",help="path to the malware file")
parser.add_argument("-t", "--timeout", dest="timeout", help="timeout in seconds, default is 60 seconds", default="60", type = int)
parser.add_argument("-i", "--internet", action="store_true", dest="internet", help = "connects to internet",  default=False)
parser.add_argument("-k", "--lkm", action="store_true", dest="lkm", help="load kernel module",  default=False)
parser.add_argument("-C", "--ufctrace", action="store_true", dest="ufstrace", help="unfiltered call trace(full trace)", default=False)
parser.add_argument("-E", "--ufemonitor", action="store_true", dest="ufemonitor", help="unfiltered system event monitoring", default=False)
parser.add_argument("-m", "--memfor", action="store_true", dest="memfor", help="memory forensics", default=False)
parser.add_argument("-M", "--vmemfor", action="store_true", dest="ver_memfor", help="verbose memory forensics(slow)", default=False)
parser.add_argument("-x", "--printhexdump", action="store_true", dest="phexdump", help="print hex dump in call trace (both filtered and unfiltered call trace)", default=False)

args = parser.parse_args()
print(args)
print("\n")

timeout = args.timeout
internet = args.internet
is_full_strace = args.ufstrace
is_femonitor = False
is_ufemonitor = args.ufemonitor
is_ver_memfor = args.ver_memfor
is_lkm = args.lkm
is_memfor = args.memfor
print_hexdump = args.phexdump


file_path = args.file
mal_file = args.file
params = ""
os.chmod(file_path,int('0777', 8))
file_name = os.path.basename(file_path)
analysis_file_path = analysis_mal_dir + "/" + file_name
filter_file_name = os.path.basename(file_path)


# Check if the given file is a ELF file
#if not (is_perl_script or is_python_script or is_shell_script or is_bash_script or is_php_script):
is_elf_file = True

# creating and cleaning the report directory (used to store the reports)
new_report_dir = report_dir + "/" + file_name
if os.path.isdir(new_report_dir):
    shutil.rmtree(new_report_dir)
os.mkdir(new_report_dir)
sandbox_logs=new_report_dir + "/sandbox_logs.txt"
static_analysis_report = new_report_dir + "/static_analysis.txt"
desk_screenshot_path = new_report_dir + "/desktop.png"
dynamic_analysis_report_dir=new_report_dir + "/dynamic_analysis"
os.mkdir(dynamic_analysis_report_dir)
pcap_output_path = dynamic_analysis_report_dir + "/output.pcap"

master_ssdeep_file = report_dir + "/ssdeep_master.txt"
# Creating the master ssdeep file
if not os.path.exists(master_ssdeep_file):
    mssdeepf = open(master_ssdeep_file, "w")
    mssdeepf.write("ssdeep,1.1--blocksize:hash:hash,filename\n")
    mssdeepf.close()

f = open(static_analysis_report, 'w')
logs = open(sandbox_logs, 'w')

logs.write("starting static analysis...!!")
logs.write("\n")
f.write( "===========================[STATIC ANALYSIS RESULTS]===========================\n\n")
static = Static(file_path)
#static = Static(mal_file)
logs.write("finding filetype..!!")
logs.write("\n")
filetype = static.fileType()
print("Filetype: ",filetype[0])
print("\n")
f.write(f"Filetype of the malware: {filetype[0]}")
f.write("\n")
f.write(f"File extension is: {filetype[1]}")
f.write("\n")
logs.write(f"filetype finding done returned with error code: {filetype[2]}")
logs.write("\n")
f.write(dash_lines)
f.write("\n")

logs.write("finding file size..!!")
logs.write("\n")
file_size = static.fileSize()
print(f"File Size : {file_size[0]}")
f.write(f"File Size: {file_size[0]}")
f.write("\n")
f.write(dash_lines)
f.write("\n")
logs.write(f"finding file size done returned with errorcode: {file_size[1]}")
logs.write("\n")

logs.write("finding md5sum..!!")
logs.write("\n")
md5sum = static.md5Sum()
print("md5sum: ",md5sum[0])
f.write(f"md5sum: {md5sum[0]}")
f.write("\n")
f.write(dash_lines)
f.write("\n")
logs.write(f"finding md5sum done returned with errorcode: {md5sum[1]}")
logs.write("\n")

logs.write("finding fuzzy hash results..!!")
fhash = static.ssdeep()
fuzzy_hash = (fhash[0]).split(",")[0]
print("ssdeep: ",fuzzy_hash)
f.write(f"ssdeep: {fuzzy_hash}")
f.write("\n")
logs.write("finding fuzzyhash done")
logs.write("\n")
logs.write("matching with existing fuzzy hashes")
logs.write("\n")
ssdeep_compare = static.ssdeep_match(master_ssdeep_file)
print("ssdeep comparison:\n")
print(ssdeep_compare)
# print dash_lines
f.write("ssdeep comparison:")
f.write("\n")
f.write(ssdeep_compare)
f.write("\n")
f.write(dash_lines)
f.write("\n")
fm = open(master_ssdeep_file, 'a')
fm.write(fuzzy_hash + "\n")
fm.close()
logs.write("matching fuzzy hash with existing fuzzy hashes done")
logs.write("\n")


logs.write("finding string related atrifacts..!!")
logs.write("\n")
f.write("string related artifacts:")
logs.write("finding ascii strings")
logs.write("\n")
f.write("\n")
asc_strings = static.asciiStrings()
# fs = open(ascii_str_file, 'w')
f.write("Ascii Strings: ")
f.write("\n")
f.write(asc_strings[0])
f.write("\n")
logs.write(f"finding ascii strings done returned with error code: {asc_strings[1]}")
logs.write("\n")

# fs.close()
print("Strings:\n")
print("\tAscii strings written to the static_analysis.txt file")

logs.write("finding unicode strings..!!")
logs.write("\n")
unc_strings = static.unicodeStrings()
f.write("Unicode Strings: ")
f.write("\n")
f.write(unc_strings[0])
f.write("\n")
f.write(dash_lines)
f.write("\n")
# fu.close()
print("\tUnicode strings written to static_analysis.txt file\n")
logs.write(f"finding unicode strings done return error code {unc_strings[1]}")
logs.write("\n")
logs.write("done with strings section")
logs.write("\n")
if yara_rules or yara_packer_rules:
    logs.write("Finding yara capabilities and packers..!!")
    logs.write("\n")
    f.write("yara packers and capabilities:")
    f.write("\n\t")
    if is_elf_file and yara_packer_rules:
        yara_packer = str(static.yaraRules(yara_packer_rules))
        f.write("Packers:")
        f.write("\n\t\t")
        f.write(yara_packer)
        f.write("\n")
        f.write(dash_lines)
        f.write("\n")
    logs.write("finding packers done")
    logs.write("\n")
    logs.write("finding yara capabilities..!!")
    logs.write("\n")
    print("done with yara packers..stored in static_analysis.txt\n")
    if yara_rules:
        yara_capabilities = str(static.yaraRules(yara_rules))
        f.write("\t"+"Malware Capabilities and classification using YARA rules:")
        f.write("\n\t")
        f.write("\t" + yara_capabilities)
        f.write("\n")
        f.write(dash_lines)
        f.write("\n")
    logs.write("finding yara capabilities done")
    logs.write("\n")
    print("done with finding yara capabilities..stored in static_analysis.txt\n")
# print "Virustotal:\n" + "\t"
# f.write("Virustotal:\n" + "\t")
# f.write("\n")
# avresults = static.virustotal(virustotal_key)
# if avresults !=None:
#     avvendors = avresults.keys()
#     avvendors.sort()
#     for avvendor in avvendors:
#         print "\t  " + avvendor + " ==> " + avresults[avvendor]
#         f.write("\t  " + avvendor + " ==> " + avresults[avvendor])
#         f.write("\n")
# print dash_lines
# f.write(dash_lines)
# f.write("\n")


if is_elf_file:
    logs.write("finding Elf file related artifacts..!!")
    logs.write("\n")
    logs.write("finding the linked dependencies..!!")
    logs.write("\n")
    f.write("ELF related artifacts:")
    f.write("\n")
    f.write("Linked Dependencies:")
    f.write("\n\t")
    depends = static.linkedDependencies()
    if depends:
        f.write(depends)
        f.write("\n")
    logs.write("done with finding linked dependencies")
    logs.write("\n")
    print("Finding linked dependencies done..stored in static_analysis.txt\n")
    
    logs.write("finding program header")
    logs.write("\n")
    f.write("Program header:")
    f.write("\n\t")
    prog_header = static.programHeader()
    if prog_header:
        f.write(prog_header)
        f.write("\n")
    logs.write("finding progeam header done")
    logs.write("\n")
    print("Finding program header done..stored in static_analysis.txt\n")
    
    logs.write("finding elf header..!!")
    logs.write("\n")
    f.write("ELF Header:")
    f.write("\n\t")
    elfh=static.elfHeader()
    if elfh:
        f.write(elfh)
        f.write("\n")
    logs.write("finding elfheader done")
    logs.write("\n")
    print("Finding program header done..stores in static_analysis.txt\n")
    
    logs.write("Finding address space section..!!")
    logs.write("\n")
    f.write("Section of Address Space:")
    f.write("\n\t")
    sect_header=static.sectionsOFAddressSpace()
    if sect_header:
        f.write(sect_header)
        f.write("\n")
    logs.write("finding section header done")
    logs.write("\n")
    print("Finding section of address space done..stored in static_analysis.txt\n")
    
    logs.write("Finding sysmbol table..!!")
    logs.write("\n")
    f.write("Symbol Table:")
    f.write("\n\t")
    sym_table=static.symbolTable()
    if sym_table:
        f.write(sym_table)
        f.write("\n")
    logs.write("finding sysmbol table done")
    logs.write("\n")
    print("Finding symbol table done..stored in static_analysis.txt\n")
    
    logs.write("Finding relocation section..!!")
    logs.write("\n")
    f.write("Relocation Section:")
    f.write("\n\t")
    rel_section=static.relocationSection()
    if rel_section:
        f.write(rel_section)
        f.write("\n")
    logs.write("finding relocation section done")
    logs.write("\n")
    print("Finding relocation section done..stored in static_analysis.txt\n")
    
    logs.write("Finding dynamic section..!!")
    logs.write("\n")
    f.write("Dynamic Section:")
    f.write("\n\t")
    dyn_section=static.dynamicSection()
    if dyn_section:
        f.write(dyn_section)
        f.write("\n")
    logs.write("Finding dynamic section done")
    logs.write("\n")
    print("Finding dynamic section done..stored in static_analysis.txt\n")
    
    logs.write("Finding Core Notes..!!")
    logs.write("\n")
    f.write("Core Notes:")
    f.write("\n\t")
    c_notes=static.coreNotes()
    if c_notes:
        f.write(c_notes)
        f.write("\n")
    logs.write("Finding core notes done")
    logs.write("\n")
    print("Finding core notes done..stored in satatic_analysis.txt\n")
    logs.write("Finding ELF file related artifacts done")
    logs.write("\n")
    f.write(dash_lines)
    f.write("\n")
    
    






# Dynamic analysis
logs.write("Starting Dyanamic Analysis..!!")
logs.write("\n")

f.write("==========================[DYNAMIC ANALYSIS RESULTS]==========================\n\n")
f.write(f"please visit ~/sandbox_reports/{file_name}/dynamic_analysis/* for dynamic analysis results")
f.write("\n")
f.write(dash_lines)
f.close()
# reverting to clean snapshot and starting vm
analysis_vm = VM(vm_id,"guestcontrol")
logs.write("setting vm credentials..!!")
logs.write("\n")
analysis_vm.setCredentials(analysis_username, analysis_password)
logs.write("setting vm credential done")
logs.write("\n")
logs.write(f"Restoring vm to a clean snapshot with snapshotname {analysis_clean_snapname}")
analysis_vm.restoreFreshVm(analysis_clean_snapname)
logs.write(f"restored vm to {analysis_clean_snapname}")
logs.write("\n")
logs.write(f"Starting VM {vm_id}..!!")
logs.write("\n")
analysis_vm.startVm()
#     print "...done..."
logs.write(f"started VM {vm_id}")
logs.write("\n")
logs.write("waiting for 15 sec to properly set the vm")
logs.write("\n")
time.sleep(15)
# # checking if internet option is given, if not starts inetsim
# if not internet:
#     iptables = Iptables(host_iface_to_sniff)
#     print "adding ip port redirection entries"
#     iptables.add_ip_port_redirect_entries()
#     iptables.display_ip_port_redirect_entries()
#     os.chdir(os.path.dirname(inetsim_path))   # newly added
#     inetsim = Inetsim(inetsim_path)
#     print "cleaning inetsim log directory"
#     inetsim.clean_log_dir(inetsim_log_dir) # cleaning the log directory
#     print "cleaning inetsim report directory"
#     inetsim.clean_report_dir(inetsim_report_dir) # cleaning the report directory
#     print "starting inetsim"
#     inetsim.start()

# print "Waiting for all the services to start"
# time.sleep(12)

# transfer file to vm
analysis_copy_file_path = analysis_mal_dir + '/'
logs.write(f"Transferring malware file to VM at {analysis_copy_file_path}")
logs.write("\n")


# print "transferring file to virtual machine"
analysis_vm.cpyToVm(mal_file, analysis_copy_file_path)
logs.write(f"Transferred malware file at {analysis_copy_file_path}")
logs.write("\n")

if is_femonitor:
    logs.write("starting sysding with filter for malware analysis..!!")
    logs.write("\n")
    analysis_vm.executeSysdig(analysis_sysdig_path, cap_filter, analysis_capture_out_file, filter_file_name)
    print("starting monitoring on the analysis machine with sysdig and with filter\n")
    time.sleep(3)

if is_ufemonitor:
    logs.write("starting sysding without filter for malware analysis..!!")
    logs.write("\n")
    analysis_vm.executeSysdigFull(analysis_sysdig_path, analysis_capture_out_file, filter_file_name)
    print("starting monitoring on the analysis machine with sysdig without filter\n")
    time.sleep(3)
logs.write("listing processes in analysis machine before running sample..!!")
logs.write("\n")
ps_dict=analysis_vm.listProcessVm()
#print(ps_dict)
pslist_before_execution=dynamic_analysis_report_dir + "/pslist_before_sample_execution.txt"
f=open(pslist_before_execution,"w")
f.write("==============================process list before sample execution===============================")
f.write("\n\n\t")
f.write("PROCESS NAME    :    PROCESS ID")
f.write("\n\t")
for ps in ps_dict:
    pair=f"{ps['pid']}    :     {ps['command']}"
    f.write(pair)
    f.write("\n\t")
f.write("\n")
f.write(dash_lines)
f.close()
logs.write(f"listed processes before execution of malware sample and written in {pslist_before_execution}")
logs.write("\n")
logs.write("making sample executable..!!")
logs.write("\n")
executable_path=analysis_copy_file_path + str(file_name)
analysis_vm.makeSampleExecutable(executable_path)
logs.write("made sample executable")
logs.write("\n")

# # starting tcpdump
logs.write("Starting execution of tcpdump..!!")
logs.write("\n")
net = TCPDUMP(host_tcpdumppath, pcap_output_path)
print("starting Network Monitor\n")
net.startTcpDump(host_iface_to_sniff, analysis_ip)
time.sleep(5)
logs.write("tcpdump started successfully")
logs.write("\n")
pslist_after_execution_of_sample=dynamic_analysis_report_dir + "/pslist_after_sample_execution.txt"
f=open(pslist_after_execution_of_sample,"w")
f.write("==============================process list after sample execution===============================")
f.write("\n\n\t")
# executing file on the analysis machine
print("executing file for " + str(timeout) + " seconds\n")

# # run the sample using strace
if is_femonitor or is_ufemonitor:
    logs.write("Starting execution of sample..!!")
    logs.write("\n")
    logs.write("listing processes after sample execution")
    logs.write("\n")
    analysis_vm.executeSample(analysis_file_path, params)
    ps_dict=analysis_vm.listProcessVm()
    f.write("PROCESS NAME    :    PROCESS ID")
    f.write("\n\t")
    for ps in ps_dict:
        pair=f"{ps['pid']}          :          {ps['command']}"
        f.write(pair)
        f.write("\n\t")
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("Listed processes at the time of execution of sample")
    logs.write("\n")
    time.sleep(timeout)
    print("...done...\n")
    logs.write(" sample Execution done")
    logs.write("\n")
else:
    logs.write("Executing sample with strace")
    logs.write("\n")
    analysis_vm.executeStrace(analysis_strace_path, analysis_strace_out_file, print_hexdump, analysis_file_path)
    time.sleep(4)
    ps_dict=analysis_vm.listProcessVm()
    f.write("PROCESS NAME    :    PROCESS ID")
    f.write("\n\t")
    for ps in ps_dict:
        pair=f"{ps['pid']}          :          {ps['command']}"
        f.write(pair)
        f.write("\n\t")
    #f.write(ps_dict)
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("Listed processes at the time of execution of sample")
    logs.write("\n")
    time.sleep(timeout)
    print("done with executing strace with malware sample...\n")
    logs.write("done with executing strace with sample")
    logs.write("\n")


# stopping sysdig
if is_femonitor or is_ufemonitor:
    logs.write("Stopping sysdig in the analysis machine")
    logs.write("\n")
    analysis_vm.stopProcessInVm("sysdig")
    logs.write("stopped sysding in vm")
    logs.write("\n")
    time.sleep(4)
else:
    logs.write("Stopping strace in the analysis machine")
    logs.write("\n")
    analysis_vm.stopProcessInVm("strace")
    logs.write("stopped strace in vm")
    logs.write("\n")
    time.sleep(4)
    
    
   

# # stopping tcpdump
logs.write("stopping tcpdump..!!")
logs.write("\n")
print("stopping Network Monitor\n")
net.stopTcpDump()
time.sleep(3)
logs.write("successfully stopped tcpdump")
logs.write("\n")


# copying sysdig capture file and strace output file to report directory

# dirs = analysis_vm.list_dir(analysis_log_outpath)
# log_files = analysis_vm.get_log_files_from_dir_list(dirs)
# if log_files:
#     for log_file in log_files:
#         log_file_path = analysis_log_outpath + '/' + log_file
#         report_file_path = new_report_dir + "/" + log_file
#         if analysis_vm.copyfromvm(log_file_path, report_file_path):
#             print "successfully copied %s to report directory " % log_file
if is_femonitor or is_ufemonitor:
    logs.write("copying sysdig syscap file from guest to host..!!")
    logs.write("\n")
    analysis_vm.cpyFromVm(analysis_capture_out_file,dynamic_analysis_report_dir)
    logs.write("copied sysdig syscap file from host to guest")
    logs.write("\n")
else:
    logs.write("copying strace syscap to host machine")
    logs.write("\n")
    analysis_vm.cpyFromVm(analysis_strace_out_file,dynamic_analysis_report_dir)
    logs.write("copied strace syscap file from host to guest")
    logs.write("\n")
# reading the sysdig captured file and dumping to a text file
if is_femonitor or is_ufemonitor:
    logs.write("converting scap to text format (human redable)..!!")
    logs.write("\n")
    cap_name = os.path.basename(analysis_capture_out_file)
    capture_out_file = dynamic_analysis_report_dir + '/' + cap_name
    fname, ext = os.path.splitext(cap_name)
    fname += ".txt"
    capture_out_txt_file = dynamic_analysis_report_dir + '/' + fname
    analysis_vm.readSysdigCaptureAndDump(host_sysdig_path, capture_out_file, capture_out_txt_file, cap_format)
    print(f"Dumped the captured data into the {capture_out_txt_file}\n")
    logs.write("converted scap to human redable text format")
    logs.write("\n")



# # printing the captured data to report file

# f.write("CALL TRACE ACTIVITIES\n")
# f.write("=======================================\n")

# if is_femonitor or is_ufemonitor:
#     sysdig_trace = analysis_vm.get_calltrace_activity(capture_out_txt_file)
#     print sysdig_trace
#     f.write(sysdig_trace)
#     f.write("\n")

# else:
#     strace_fname = os.path.basename(analysis_strace_out_file)
#     strace_out_fname = new_report_dir + "/" + strace_fname
#     strace_output = analysis_vm.get_calltrace_activity(strace_out_fname)
#     print strace_output
#     f.write(strace_output)
#     f.write("\n")


logs.write("capturing desktop screenshot of vm..!!")
logs.write("\n")
print("capturing desktop screenshot of vm")
analysis_vm.takeScreenShot(desk_screenshot_path)
#     print "done, desktop screenshot saved as %s" % desk_screenshot_path
logs.write("capturing desktop  screenshot of vm")
logs.write("\n")

logs.write("done with analysis..suspending vm..!!")
print("suspending virtual machine")
analysis_vm.suspendVm()

logs.write("Getting network activities in human redable format")
logs.write("\n")
net_activities = dynamic_analysis_report_dir + "/network_traffic_analysis.txt"
f=open(net_activities,"w")
f.write("==============================Network Traffic Analysis===============================")
f.write("\n")
# # get and display tshark summary
f.write("===============================DNS SUMMARY=============================\n")
f.write("\n\t")
logs.write("Getting DNS summary..!!")
logs.write("\n")
dns_summary = net.dnsSummaryReport()
# print dns_summary
f.write(str(dns_summary))
f.write("\n\n")
logs.write(f"Got the DNS summary dumped into {net_activities}")
logs.write("\n")
logs.write("getting TCP Conversations")
logs.write("\n")
f.write("===============================TCP CONVERSATIONS=========================\n")
f.write("\n\t")
# f.write("=======================================\n\n")
tcp_conversations = net.tcpConversationReport()
# print tcp_conversations
f.write(str(tcp_conversations))
f.write("\n\n")
f.write(dash_lines)
f.close()
logs.write(f"Got the TCP conversation report dumped into the {net_activities}")


# # stopping inetsim, if internet option is not given
# if not internet:
#     inetsim.stop()
#     time.sleep(8)  # This is requried so that all the inetsim services are stopped
#     f.write("INETSIM LOG DATA\n")
#     f.write("=======================================\n\n")
#     inetsim_log_data = inetsim.get_inetsim_log_data()
#     print inetsim_log_data
#     f.write(inetsim_log_data)
#     f.write("\n")
#     f.write("INETSIM REPORT DATA\n")
#     f.write("========================================\n\n")
#     inetsim_report_data = inetsim.get_inetsim_report_data()
#     print inetsim_report_data
#     f.write(inetsim_report_data)
#     f.write("\n")
#     print "done"
#     print "\n"

#     print "deleting ip port redirection entries"
#     iptables.delete_ip_port_redirect_entries()
#     iptables.display_ip_port_redirect_entries()
logs.write("over...!!!")
logs.write("\n")
logs.write(dash_lines)
logs.close()

# if is_memfor or is_ver_memfor:

#     f.write("=======================[MEMORY ANALYSIS RESULTS]=======================\n\n")

#     # starting memory forensics
#     print "Starting Memory Analysis using Volatility"
#     vol = Volatility(py_path, vol_path, analysis_vm.get_vmmem(), mem_image_profile)

#     f.write("PSLIST\n")
#     f.write("=======================================\n\n")
#     pslist = vol.pslist()
#     print pslist
#     f.write(pslist)
#     f.write("\n")

#     f.write("PSTREE\n")
#     f.write("=======================================\n\n")
#     pstree = vol.pstree()
#     print pstree
#     f.write(pstree)
#     f.write("\n")

#     f.write("Pid Hash Table\n")
#     f.write("=======================================\n\n")
#     pidhashtable = vol.pidhashtable()
#     print pidhashtable
#     f.write(pidhashtable)
#     f.write("\n")

#     f.write("PROCESS COMMAND LINE ARGUMENTS\n")
#     f.write("=======================================\n\n")
#     psaux = vol.psaux()
#     print psaux
#     f.write(psaux)
#     f.write("\n")

#     f.write("PSXVIEW\n")
#     f.write("=======================================\n\n")
#     psxview = vol.psxview()
#     print psxview
#     f.write(psxview)
#     f.write("\n")

#     f.write("PROCESS ENVIRONMENT\n")
#     f.write("=======================================\n\n")
#     psenv = vol.psenv()
#     print psenv
#     f.write(psenv)
#     f.write("\n")

#     f.write("THREADS\n")
#     f.write("=======================================\n\n")
#     threads = vol.threads()
#     print threads
#     f.write(threads)
#     f.write("\n")

#     f.write("NETWORK CONNECTIONS\n")
#     f.write("=======================================\n\n")
#     connections = vol.netstat()
#     print connections
#     f.write(connections)
#     f.write("\n")

#     f.write("INTERFACE INFORMATION\n")
#     f.write("=======================================\n\n")
#     ifconfig = vol.ifconfig()
#     print ifconfig
#     f.write(ifconfig)
#     f.write("\n")

#     f.write("PROCESSES WITH RAW SOCKETS\n")
#     f.write("=======================================\n\n")
#     raw_sockets = vol.list_raw()
#     print raw_sockets
#     f.write(raw_sockets)
#     f.write("\n")

#     f.write("LIBRARY LIST\n")
#     f.write("========================================\n\n")
#     lib_list = vol.library_list()
#     print lib_list
#     f.write(lib_list)
#     f.write("\n")


#     f.write("Ldrmodules\n")
#     f.write("========================================\n\n")
#     ldrmodules = vol.ldrmodules()
#     print ldrmodules
#     f.write(ldrmodules)
#     f.write("\n")

#     f.write("KERNEL MODULES\n")
#     f.write("=========================================\n\n")
#     modules = vol.lsmod()
#     print modules
#     f.write(modules)
#     f.write("\n")

#     f.write("MODULES HIDDEN FROM MODULE LIST (PRESENT IN SYSFS)\n")
#     f.write("=========================================\n\n")
#     chk_modules = vol.check_modules()
#     print chk_modules
#     f.write(chk_modules)
#     f.write("\n")

#     f.write("MODULES HIDDEN FROM MODULE LIST and SYSFS\n")
#     f.write("=========================================\n\n")
#     hidden_modules = vol.hidden_modules()
#     print hidden_modules
#     f.write(hidden_modules)
#     f.write("\n")
    
#     f.write("FILES OPENED WITHIN KERNEL\n")
#     f.write("=========================================\n\n")
#     krnl_opened_files = vol.kernel_opened_files()
#     print krnl_opened_files
#     f.write(krnl_opened_files)
#     f.write("\n")

#     f.write("PROCESSES SHARING CREDENTIAL STRUCTURES\n")
#     f.write("=========================================\n\n")
#     proc_creds = vol.check_creds()
#     print proc_creds
#     f.write(proc_creds)
#     f.write("\n")

#     f.write("KEYBOARD NOTIFIERS\n")
#     f.write("=========================================\n\n")
#     key_notfs = vol.keyboard_notifiers()
#     print key_notfs
#     f.write(key_notfs)
#     f.write("\n")
    
#     f.write("TTY HOOKS\n")
#     f.write("=========================================\n\n")
#     tty_hooks = vol.check_tty()
#     print tty_hooks
#     f.write(tty_hooks)
#     f.write("\n")

#     f.write("SYSTEM CALL TABLE MODIFICATION\n")
#     f.write("=========================================\n\n")
#     chk_syscall = vol.check_syscall()
#     print chk_syscall
#     f.write(chk_syscall)
#     f.write("\n")

#     f.write("BASH HISTORY\n")
#     f.write("=========================================\n\n")
#     bash_hist = vol.bash_history()
#     print bash_hist
#     f.write(bash_hist)
#     f.write("\n")

#     f.write("MODIFIED FILE OPERATION STRUCTURES\n")
#     f.write("=========================================\n\n")
#     mod_fop = vol.check_fop()
#     print mod_fop
#     f.write(mod_fop)
#     f.write("\n")

#     f.write("HOOKED NETWORK OPERTATION FUNCTION POINTERS\n")
#     f.write("=========================================\n\n")
#     hooked_af = vol.check_afinfo()
#     print hooked_af
#     f.write(hooked_af)
#     f.write("\n")

#     f.write("NETFILTER HOOKS\n")
#     f.write("=========================================\n\n")
#     netfilter_hooks = vol.netfilter()
#     print netfilter_hooks
#     f.write(netfilter_hooks)
#     f.write("\n")


#     f.write("MALFIND\n")
#     f.write("=========================================\n\n")
#     malfind = vol.malfind()
#     print malfind
#     f.write(malfind)
#     f.write("\n")
    
#     if is_ver_memfor:
        
#         f.write("PLT HOOK\n")
#         f.write("=========================================\n\n")
#         plthooks = vol.plthook()
#         print plthooks
#         f.write(plthooks)
#         f.write("\n")

#         f.write("USERLAND API HOOKS\n")
#         f.write("=========================================\n\n")
#         apihooks = vol.apihooks()
#         print apihooks
#         f.write(apihooks)
#         f.write("\n")
        
#         f.write("INLINE KERNEL HOOKS\n")
#         f.write("=========================================\n\n")
#         in_kernel_hooks = vol.check_inline_kernel()
#         print in_kernel_hooks
#         f.write(in_kernel_hooks)
#         f.write("\n")


# f.close()

# print "Final report is stored in %s" % new_report_dir


# In[ ]:




