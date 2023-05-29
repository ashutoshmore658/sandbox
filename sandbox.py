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
from file_operations import*
from json_parser_network_traffic import*
from json_parser_static_analysis import*
import argparse
import shutil
import time
import os
from tqdm import tqdm
import json


# checking if filename and arguments are provided
if len(sys.argv) <= 1:
    print("Please give some options, type -h or --help for more information")
    sys.exit()

# adding and parsing  options
parser = argparse.ArgumentParser(description='Usage: %prog [Options] <file> [args]')
parser.add_argument("file",help="path to the malware file")
parser.add_argument("-t", "--timeout", dest="timeout", help="timeout in seconds, default is 60 seconds", default="60", type = int)
parser.add_argument("-f", "--fileops", action="store_true", dest="fileops", help="get file operations in json format", default=False)
#parser.add_argument("-i", "--internet", action="store_true", dest="internet", help = "connects to internet",  default=False)
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
#internet = args.internet
is_full_strace = args.ufstrace
is_femonitor = False
print_hexdump = args.phexdump
is_ufemonitor = args.ufemonitor
is_fileops = args.fileops
if is_fileops == True:
    print_hexdump = False
    is_ufemonitor = False
is_ver_memfor = args.ver_memfor
is_lkm = args.lkm
is_memfor = args.memfor



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
json_report_dir = new_report_dir + "/" + "Complete Analysis in Json"
os.mkdir(json_report_dir)
json_report = json_report_dir + "/" + "Analysis_report.json"

#creating memory dumps directory if not created
if not os.path.isdir(mem_dump_dir) and (is_memfor or is_ver_memfor):
    os.mkdir(mem_dump_dir)
mem_dump_path = ""
if is_memfor or is_ver_memfor:
    mem_dump_path = mem_dump_dir + "/" + file_name + ".vmem"
    if os.path.exists(mem_dump_path):
        os.remove(mem_dump_path)
    

master_ssdeep_file = report_dir + "/ssdeep_master.txt"
# Creating the master ssdeep file
if not os.path.exists(master_ssdeep_file):
    mssdeepf = open(master_ssdeep_file, "w")
    mssdeepf.write("ssdeep,1.1--blocksize:hash:hash,filename\n")
    mssdeepf.close()


analysis_dict = {}    

f = open(static_analysis_report, 'w')
logs = open(sandbox_logs, 'w')

logs.write("starting static analysis...!!")
logs.write("\n")
f.write( "===========================[STATIC ANALYSIS RESULTS]===========================\n\n")
static = Static(file_path)

json_static = JsonParserStatic()

static_analysis_dict = {}
#static = Static(mal_file)
logs.write("finding filetype..!!")
logs.write("\n")
filetype = static.fileType()
print("Filetype: ",filetype[0])
print("\n")
static_analysis_dict["File Type"] = json_static.parseFileType(filetype[0])
f.write(f"Filetype of the malware: {filetype[0]}")
f.write("\n")
f.write(f"File extension is: {filetype[1]}")
f.write("\n")
static_analysis_dict["File Extension"] = json_static.parseFileExtension(filetype[1])
logs.write(f"filetype finding done returned with error code: {filetype[2]}")
logs.write("\n")
f.write(dash_lines)
f.write("\n")

logs.write("finding file size..!!")
logs.write("\n")
file_size = static.fileSize()
print(f"File Size : {file_size[0]}")
static_analysis_dict["File Size"] = json_static.parseFileSize(file_size[0])
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
static_analysis_dict["Md5Sum"] = json_static.parseMd5Sum(md5sum[0])
f.write(f"md5sum: {md5sum[0]}")
f.write("\n")
f.write(dash_lines)
f.write("\n")
logs.write(f"finding md5sum done returned with errorcode: {md5sum[1]}")
logs.write("\n")

logs.write("finding fuzzy hash results..!!")
fhash = static.ssdeep(master_ssdeep_file)
fuzzy_hash = (fhash[0]).split(",")[0]
print("ssdeep: ",fuzzy_hash)
f.write(f"ssdeep: {fuzzy_hash}")
static_analysis_dict["Fuzzy Hash"] = json_static.parseFuzzyHash(fuzzy_hash)
f.write("\n")
logs.write("finding fuzzyhash done")
logs.write("\n")
logs.write("matching with existing fuzzy hashes")
logs.write("\n")
ssdeep_compare = static.ssdeep_match(master_ssdeep_file)
print("ssdeep comparison:\n")
print(ssdeep_compare)
#static_analysis_dict["Fuzzy Hash Matching"] = json_static.parseFuzzyHashMatching(ssdeep_compare)
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

f.write("Ascii Strings: ")
f.write("\n")
f.write(asc_strings[0])
f.write("\n")
logs.write(f"finding ascii strings done returned with error code: {asc_strings[1]}")
logs.write("\n")


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
static_analysis_dict["Strings"] = json_static.parseStrings(asc_strings[0], unc_strings[0])
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
static_analysis_dict["Yara Matching"] = json_static.parseYara(yara_packer, yara_capabilities)
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
    static_analysis_dict["Linked Dependency"] = json_static.parseElfLinkedDepend(depends)
    
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
    static_analysis_dict["Program Header"] = json_static.parseElfProgramHeader(prog_header)
    
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
    static_analysis_dict["ELF Header"] = json_static.parseElfHeader(elfh)
    
    
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
    static_analysis_dict["Symbol Table"] = json_static.parseSymbolTable(sym_table)
    
    
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
    static_analysis_dict["Relocation Section"] = json_static.parseRelocationSection(rel_section)
    
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
    static_analysis_dict["Core Notes"] = json_static.parseCoreNotes(c_notes)
    
analysis_dict["Static Analysis"] = static_analysis_dict
    
    






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

if is_memfor or is_ver_memfor:
    logs.write("Capturing memory Dump..!!")
    print("capturing memory dump..\n")
    logs.write("\n")
    o = tqdm(analysis_vm.dumpVmMem(mem_dump_path))
    print(o)
    print(f"captured memory dump...stored in {mem_dump_path}\n")
    logs.write("captured memory dump")
    logs.write("\n")
    

logs.write("done with analysis..suspending vm..!!")
logs.write("\n")
print("suspending virtual machine")
analysis_vm.suspendVm()
logs.write("suspended vm")
logs.write("\n")
print("VM suspended !")

print("getting network traffic in human readable format..\n\n")

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
json_net = jsonParserNetwork()
network_dict = {}
dns_summary = net.dnsSummaryReport()
network_dict["DNS Summary"] = json_net.parseDnsTraffic(dns_summary)
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
network_dict["TCP Summary"] = json_net.parseTcpTraffic(tcp_conversations)
analysis_dict["Network Traffic"] = network_dict
print("Got network traffic in json format...\n\n")
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


if is_memfor or is_ver_memfor:
    memory_analysis_report_dir = new_report_dir + "/" + "Memory Artifacts"
    if not os.path.isdir(memory_analysis_report_dir):
        os.mkdir(memory_analysis_report_dir)
    
    logs.write("Finding all attributes in memory dump using Volatility3")
    logs.write("\n")
    mem = Memory(py_path, voltility_path, mem_dump_path, memory_profile_dir)
    
    banners_report = memory_analysis_report_dir + "/" + "banners.txt"
    bash_history_report = memory_analysis_report_dir + "/" + "bash_history.txt"
    credential_structure_sharing_report = memory_analysis_report_dir + "/" + "credential_structure_sharing_report.txt"
    altered_idt_report = memory_analysis_report_dir + "/" + "altered_idt.txt"
    module_list_report = memory_analysis_report_dir + "/" + "module_list.txt"
    syscall_table_report = memory_analysis_report_dir + "/" + "syscall_table.txt"
    memory_mapped_elf_report = memory_analysis_report_dir + "/" + "memory_mapped_elf.txt"
    process_env_variables_report = memory_analysis_report_dir + "/" + "process_with_environment_variables.txt"
    keyboard_notifiers_report = memory_analysis_report_dir + "/" + "keyboard_notifiers.txt"
    loaded_kmods_report = memory_analysis_report_dir + "/" + "loaded_kernel_modules.txt"
    memory_maps_of_all_processes = memory_analysis_report_dir + "/" + "memory_maps_all_procs.txt"  
    memory_maps_of_processes  = memory_analysis_report_dir + "/" + "memory_maps_procs.txt"
    procs_with_potentially_injected_codes_report = memory_analysis_report_dir + "/" + "processes_with_potentially_injected_codes.txt"
    procs_with_mount_space = memory_analysis_report_dir + "/" + "processes_with_mount_spaces.txt"
    procs_with_commands = memory_analysis_report_dir + "/" + "processes_with_mother_commands.txt"
    all_procs = memory_analysis_report_dir + "/" + "all_processes.txt"
    procs_scans = memory_analysis_report_dir + "/" + "process_scans.txt"
    procs_tree = memory_analysis_report_dir + "/" + "process_tree.txt"
    procs_network_info = memory_analysis_report_dir + "/" + "process_network_information.txt"
    tty_devices_report = memory_analysis_report_dir + "/" + "all_tty_devices.txt"
    

    #f.write("=======================[MEMORY ANALYSIS RESULTS]=======================\n\n")
    print("\n")
    print("\n")
    print("Starting memory forensics using Volatility3..!!\n")
    logs.write("getting banners..")
    logs.write("\n")
    print("getting bannerss....!!\n")
    banners = mem.getBanners()
    logs.write("got banners")
    logs.write("\n")
    f = open(banners_report,"w")
    f.write("=======================[Banners]=======================\n\n\n\n\t")
    f.write(banners[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    print("got banners")
    
    logs.write("Getting bash history from memory...")
    logs.write("\n")
    print("getting basg history....!!\n")
    bash_history = mem.getBashHistory()
    logs.write("got bash history")
    logs.write("\n")
    f = open(bash_history_report,"w")
    f.write("=======================[Bash History]=======================\n\n\n\n\t")
    f.write(bash_history[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    print("got bash history...\n")
    
    logs.write("Getting credential structure sharing processes")
    logs.write("\n")
    print("getting credential structure sharing...!!\n")
    cred_strct = mem.getCredentialStructureSharing()
    f = open(credential_structure_sharing_report,"w")
    f.write("=======================[Credential Structure Sharing]=======================\n\n\n\n\t")
    if cred_strct[1] == []:
        f.write("no such pids available !!")
        f.write("\n")
    else:
        f.write(cred_strct[0])
        f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got credential structure sharing pids")
    logs.write("\n")
    print("got credential structure sharing....\n")
    
    logs.write("Getting altered IDT")
    logs.write("\n")
    print("getting altered IDT..!!\n")
    altered_idt = mem.getIdtAltered()
    f = open(altered_idt_report,"w")
    f.write("=======================[Altered IDT]=======================\n\n\n\n\t")
    f.write(altered_idt[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got altered IDT")
    logs.write("\n")
    print("got altered IDT...!!\n")
    
    logs.write("getting module lists")
    logs.write("\n")
    print("getting module lists...!!!\n")
    f = open(module_list_report,"w")
    f.write("=======================[Module List]=======================\n\n\n\n\t")
    module_list = mem.getModuleList()
    if module_list[1] == []:
        f.write("No module list found")
        f.write("\n")
    else:
        f.write(module_list)
        f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("Got module list")
    logs.write("\n")
    print("got module list.....!!!\n")
    
    logs.write("getting Syscall Table")
    logs.write("\n")
    print("getting syscall table...!!\n")
    syscall_table = mem.getSyscallTable()
    logs.write("got syscall table report")
    logs.write("\n")
    f = open(syscall_table_report,"w")
    f.write("=======================[Syscall Table]=======================\n\n\n\n\t")
    f.write(syscall_table[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    print("got syscall table..!!\n")
    
    logs.write("getting memory mapped elf")
    logs.write("\n")
    print("getting memory mapped ELF...!!!\n")
    memory_mapped_elf = mem.getMemoryMappedElf()
    logs.write("got memory mapped elf")
    logs.write("\n")
    f = open(memory_mapped_elf_report,"w")
    f.write("=======================[Memory Mapped ELF]=======================\n\n\n\n\t")
    f.write(memory_mapped_elf[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    print("got memory mapped ELF...!!\n")
    
    logs.write("getting processes with environment variables")
    logs.write("\n")
    print("getting processes with environment variables...!!!\n")
    process_with_env = mem.getProcessesWithEnvVars()
    f = open(process_env_variables_report,"w")
    f.write("=======================[Process With Environment Variables]=======================\n\n\n\n\t")
    f.write(process_with_env[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got process with environment variables")
    logs.write("\n")
    print("got processes with environment variables...!!\n")
    
    logs.write("getting keyboard notifiers")
    logs.write("\n")
    print("getting keyboard notifiers...!!\n")
    keyboard_notifiers = mem.getKeyboardNotifiers()
    f = open(keyboard_notifiers_report,"w")
    f.write("=======================[KeyBoard Notifiers]=======================\n\n\n\n\t")
    if keyboard_notifiers == []:
        f.write("No keyboard notifiers found")
        f.write("\n")
    else:
        f.write(keyboard_notifiers[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got keyboard notifiers")
    logs.write("\n")
    print("got keyboard notifiers...!!\n")
    
    logs.write("getting loaded kernel modules")
    logs.write("\n")
    print("getting loaded kernel modules...!!\n")
    loaded_kmods = mem.getLoadedKernelModules()
    f = open(loaded_kmods_report, "w")
    f.write("=======================[Loaded Kernel Modules]=======================\n\n\n\n\t")
    f.write(loaded_kmods[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got loaded kernel modules")
    logs.write("\n")
    print("got loaded kernel modules...!!\n")
    
    logs.write("get memory maps of all processes")
    logs.write("\n")
    print("getting memory maps of all processes...!!!\n")
    mmaps_of_all_processes = mem.getMemoryMapsOfAllProcesses()
    f = open(memory_maps_of_all_processes,"w")
    f.write("=======================[Memory Maps Of All Processes]=======================\n\n\n\n\t")
    f.write(mmaps_of_all_processes[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got memory maps of all processes")
    logs.write("\n")
    print("got memory maps of all processes...!!\n")
    
    
    logs.write("memory maps of processes")
    logs.write("\n")
    print("getting memory maps of processes...!!\n")
    mmaps_of_processes = mem.getMemoryMapsOfProcesses()
    f = open(memory_maps_of_processes,"w")
    f.write("=======================[Memory Maps Of Processes]=======================\n\n\n\n\t")
    f.write(mmaps_of_processes[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got memory maps of processes")
    logs.write("\n")
    print("got memory maps of processes...!!\n")
    
    logs.write("processes with potentially injected codes")
    logs.write("\n")
    print("getting processes potentially injected codes...!!\n")
    procs_with_potentially_injected_codes = mem.getProcessesWithPotentiallyInjectedCode()
    f = open(procs_with_potentially_injected_codes_report,"w")
    f.write("=======================[Processes With Potentially Injected Codes====\n\n\n\n\t")
    f.write(procs_with_potentially_injected_codes[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got processes with potentially injected codes")
    logs.write("\n")
    print("got processes with potentially injected codes...!!\n")
    
    logs.write("get processes with their mount spaces")
    logs.write("\n")
    print("getting processes with mount spaces...!!\n")
    procs_with_mount_spaces = mem.getProcessesMountSpaces()
    f = open(procs_with_mount_space,"w")
    f.write("=======================[Processes With Mount Spaces]=======================\n\n\n\n\t")
    f.write(str(procs_with_mount_spaces[0]))
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got processes with their mount spaces")
    logs.write("\n")
    print("got processes with potentially injected codes...!!\n")
    
    logs.write("get Processes with their mother commands")
    logs.write("\n")
    print("getting processes with their mother commands...!!!\n")
    processes_with_commands = mem.getProcessesWithCommands()
    f = open(procs_with_commands,"w")
    f.write("=======================[Processes With Their Mother Commands]=======================\n\n\n\n\t")
    f.write(processes_with_commands[0])
    f.write("\n")
    f.write(dash_lines)
    f.close()
    logs.write("got proceses with their mother commands")
    logs.write("\n")
    print("got processes with their mother commands")
    
    logs.write("get all processes")
    logs.write("\n")
    print("getting all processes...!!\n")
    all_process  = mem.getAllProcesses()
    f = open(all_procs,"w")
    f.write("=======================[List of All Process]=======================\n\n\n\n\t")
    f.write(all_process[0])
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")
    f.close()
    logs.write("got all processes")
    logs.write("\n")
    print("got all processes...!!\n")
    
    logs.write("get process scans")
    logs.write("\n")
    print("getting process scans..!!!\n")
    process_scans = mem.getProcessScans()
    f = open(procs_scans,"w")
    f.write("=======================[Process Scans]=======================\n\n\n\n\t")
    f.write(process_scans[0])
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")
    f.close()
    logs.write("got process scans")
    logs.write("\n")
    print("got processe scans...!!!\n")
    
    logs.write("getting process tree")
    logs.write("\n")
    print("getting process trees...!!!\n")
    process_tree = mem.getProcessTree()
    f = open(procs_tree,"w")
    f.write("=======================[Process Tree]=======================\n\n\n\n\t")
    f.write(process_tree[0])
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")
    f.close()
    logs.write("got process tree")
    logs.write("\n")
    print("got process trees...!!!\n")
    
    logs.write("getting process network information")
    logs.write("\n")
    print("getting process network information...!!!\n")
    process_network_info = mem.getNetworkInfoOfAllProcess()
    f = open(procs_network_info,"w")
    f.write("=======================[Process Network Information]=======================\n\n\n\n\t")
    f.write(process_network_info[0])
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")
    f.close()
    logs.write("got process networtk information")
    logs.write("\n")
    print("got process network information...!!!\n")
    
    logs.write("getting TTY devices")
    logs.write("\n")
    print("getting tty devices..!!\n")
    tty_devices = mem.getTtyDevices()
    f = open(tty_devices_report,"w")
    f.write("=======================[TTY Devices]=======================\n\n\n\n\t")
    f.write(tty_devices[0])
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")
    f.close()
    logs.write("got all tty devices")
    logs.write("\n")
    print("got tty devices..!!\n")
    print("\n\n")
    print("Done with memory analysis please visit sandbox_reports directory for results...!!\n")
    
    
if is_fileops:
    print("starting file operations monitor..!!\n\n")
    logs.write("starting file operations monitor..")
    logs.write("\n")
    scap_file = dynamic_analysis_report_dir + "/" + "sample_strace_out.txt"
    fops = FileOperations(scap_file)
    file_operations_dict = fops.jsonParser()
    analysis_dict["File Operations"] = file_operations_dict
    logs.write("file operations done..!!\n")
    print("file operations done..look in to json file....!!\n\n")
    
    
with open(json_report, "w") as file:
    json.dump(analysis_dict,file)
    
logs.write("Done with total analysis..!!")
logs.close()
    
    
   
    
    



