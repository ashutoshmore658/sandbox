#!/usr/bin/env python
# coding: utf-8

# In[2]:


import shutil
import subprocess
from subprocess import *
import sys
import re
import os
import jc

# In[48]:


class VM():
    def __init__(self,virtual_machine,control):
        self.vm=virtual_machine
        self.ctrl=control
        self.u_name=""
        self.passwd=""
    def setCredentials(self,user,password):
        self.u_name=user
        self.passwd=password
    def restoreFreshVm(self,restore_to_version):
        c_proc=subprocess.Popen(['VBoxManage','snapshot',self.vm,'restore',restore_to_version],stdout=PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if vm_op:
            print(vm_op)
            print('RESTORE VM--done!!..exiting\n')
            c_proc.kill()
        else:
            return 1
    def startVm(self):
        c_proc=subprocess.Popen(['VBoxManage','startvm',self.vm, '--type', 'headless'],stdout=PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if vm_op:
            print(vm_op)
            print('START VM--done!!..exiting')
            c_proc.kill()
        else:
            return 1
    def cpyToVm(self,hsource,gdestination):
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'copyto','--username',self.u_name,'--password',self.passwd,'--target-directory',gdestination,hsource],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if not vm_op:
            print(vm_op)
            print('COPY FILE FROM HOST TO GUEST--done!!..exiting')
            c_proc.kill()
        else:
            return 1
    def cpyFromVm(self,gsource,hdestination):
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'copyfrom','--username',self.u_name,'--password',self.passwd,'--target-directory',hdestination,gsource],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if not vm_op:
            print(vm_op)
            print('COPY RESULT FROM GUEST TO HOST--done!!..exiting')
            c_proc.kill()
        else:
            return 1
    def takeScreenShot(self,screenshotname):
        c_proc=subprocess.Popen(['VBoxManage','controlvm',self.vm,'screenshotpng',screenshotname],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if not vm_op:
            print(vm_op)
            print('SCREENSHOT CAPTURED--done!!..exiting')
            c_proc.kill()
        else:
            return 1
    def suspendVm(self):
        c_proc=subprocess.Popen(['VBoxManage','controlvm',self.vm,'savestate'],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if not vm_op:
            print('SAVED VM SATATE..\n')
            print('done!!..exiting')
            c_proc.kill()
        else:
            return 1
    def stopVm(self):
        c_proc=subprocess.Popen(['VBoxManage','controlvm',self.vm,'poweroff'],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        if not vm_op:
            print('STOPPED VM..done!!..exiting')
            c_proc.kill()
        else:
            return 1
    def listProcessVm(self):
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/ps','--username',self.u_name,'--password',self.passwd, '--', 'ps', 'aux'],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        ps_dict= {}
        ps_dict = jc.parse('ps', vm_op)
        '''ps_list=vm_op.split('\n')[1:len(vm_op)]
        ps_dict={}
        for ps in ps_list:
            print(ps)
            ps_id = 0
            ps_name=ps[26:len(ps)]
            if ps:
                ps_id=int(ps[0:7].strip())
            ps_dict[ps_name]=ps_id
        return ps_dict'''
        return ps_dict
    def getProcessIdInVm(self,process_name):
        proc_name=process_name
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/ps','--username',self.u_name,'--password',self.passwd],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        ps_list=vm_op.split('\n')[1:len(vm_op)]
        ps_dict={}
        for ps in ps_list:
            ps_name=ps[26:len(ps)]
            ps_id=ps[0:7].strip()
            ps_dict[ps_name]=ps_id
        ps_id=ps_dict[process_name]
        return [process_name,ps_id]
    
    def stopProcessInVm(self,process_name):
        proc_name=process_name
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/ps','--username',self.u_name,'--password',self.passwd],stdout=subprocess.PIPE)
        vm_op=(c_proc.communicate()[0]).decode()
        ps_list=vm_op.split('\n')[1:len(vm_op)]
        ps_dict={}
        for ps in ps_list:
            ps_name=ps[26:len(ps)]
            ps_id=ps[0:7].strip()
            ps_dict[ps_name]=ps_id
        if proc_name in ps_dict.keys():
            proc_id=ps_dict[proc_name]
            print(f'process {proc_name} was started at {proc_id} in VM')
            print(f'killing process{proc_name} in vm!!!')
            p = r"([P]*ID=\d+)"
            c_proc=subprocess.Popen(['VBoxManage','guestcontrol',self.vm,'list','all'],stdout=subprocess.PIPE)
            vm_op=((c_proc.communicate()[0]).decode())
            pid_sessid = re.findall(p, vm_op)
            pid_sessid_dict={}
            for pid in range(0,len(pid_sessid)-1,2):
                pid_sessid_dict[(pid_sessid[pid+1][4:len(pid_sessid[pid+1])]).strip()]=(pid_sessid[pid][3:len(pid_sessid[pid])]).strip()
            proc_sessid=pid_sessid_dict[proc_id]
            kill_proc=subprocess.check_call(['VBoxManage',self.ctrl,self.vm,'closeprocess','--session-id',proc_sessid,proc_id])
            print(f'killed {proc_name}...!!!')
        else:
            print(f'!!!..{proc_name} is NOT SPAWNED YET')
    def executeSample(self,malware_file,args):
        cmd=['VBoxManage',self.ctrl,self.vm,'run','--exe',malware_file,'--username',self.u_name,'--password',self.passwd]
        cmd.extend(args)
        o=subprocess.Popen(cmd)
        stdop=(o.stdout)
        return stdop
    def makeSampleExecutable(self,malware_file):
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/chmod','--username',self.u_name,'--password',self.passwd,'chmod/arg0','0777',malware_file])
        c_proc=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/chmod','--username',self.u_name,'--password',self.passwd,'chmod/arg0','+x',malware_file])
        print('Make sample executable in VM....done!!')
    def executeSysdig(self,sysdig_path,capture_filter,analysis_capture_out_file,filter_file_name):
        capture_filter = capture_filter + " " + "and (proc.name=" + filter_file_name[:15] + " " + "or proc.aname=" + filter_file_name[:15] + ")"
        subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe',sysdig_path,'--username',self.u_name,'--password',self.passwd,'--','sysdig/arg0',capture_filter,'-w',analysis_capture_out_file])
    def executeSysdigFull(self,sysdig_path,analysis_capture_out_file,filter_file_name):
        print(filter_file_name)
        capture_filter = "proc.name=" + filter_file_name[:15] + " " + "or proc.aname=" + filter_file_name[:15]
        subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe',sysdig_path,'--username',self.u_name,'--password',self.passwd,'--','sysdig/arg0',capture_filter,'-w',analysis_capture_out_file])
    
    def executeStrace(self,strace_path,strace_output_file,print_hexdump,malware_file):
        args=""
        if print_hexdump:
            cmd=['VBoxManage',self.ctrl,self.vm,'run','--exe',strace_path,'--username',self.u_name,'--password',self.passwd,'--','strace/arg0','-o',strace_output_file,'-s','64','-eread=all','-ewrite=all','-f',malware_file]
        else:
            cmd=['VBoxManage',self.ctrl,self.vm,'run','--exe',strace_path,'--username',self.u_name,'--password',self.passwd,'--','strace/arg0','-o',strace_output_file,'-s','216','-f',malware_file]
        cmd.extend(args)
        subprocess.Popen(cmd)
    
    def readSysdigCaptureAndDump(self,host_sysdig_path,analysis_capture_out_file,capture_out_txt_file,capture_format):
        capture_format='"'+capture_format+'"'
        c_proc=subprocess.Popen([host_sysdig_path,' ','-p',capture_format,' ','-r',' ',analysis_capture_out_file,'>',capture_out_txt_file])
        c_proc.wait()
    def getCallTraceActivity(self,capture_out_file):
        call_trace=open(capture_out_file).read()
        return call_trace
    
    def dumpVmMem(self,mem_image):
        try:
            c_proc=subprocess.Popen(['VBoxManage','debugvm',self.vm,'dumpvmcore','--filename',mem_image],stdout=subprocess.PIPE)
            return "Done"
        except subprocess.CalledProcessError as e:
            return e.returncode
        except OSError as e:
            return e


# In[14]:


class TCPDUMP():
    def __init__(self,tcpdump_path,tcpdump_output_path):
        if not os.path.isfile(tcpdump_path):
            print('No TcpDump at the given location:',tcpdump_path)
            print('exiting..!!')
            sys.exit('Exited because of NO FILE AT GIVEN LOCATION')
        self.tcpdump_path=tcpdump_path
        self.tcpdump_output_pcap_path=tcpdump_output_path
        self.c_proc=None
    def startTcpDump(self,network_interface,ip_addr):
        self.c_proc=subprocess.Popen([self.tcpdump_path,'-n','-i',network_interface,'host %s'%ip_addr,'-w',self.tcpdump_output_pcap_path])
    def stopTcpDump(self):
        if self.c_proc != None:
            print('Terminating TCPDUMP....')
            self.c_proc.terminate()
            print('Terminated..!!')
        else:
            print("TCPDUMP was not spawned")
    def dnsSummaryReport(self):
        c_proc = subprocess.Popen([self.tcpdump_path, '-n', '-r', self.tcpdump_output_pcap_path, "udp and port 53"], stdout=subprocess.PIPE)
        dns_query_summary= (c_proc.communicate()[0]).decode()
        return dns_query_summary
    def tcpConversationReport(self):
        c_proc = subprocess.Popen([self.tcpdump_path,'-n', '-q', '-r', self.tcpdump_output_pcap_path, "tcp"], stdout=subprocess.PIPE)
        tcp_conv_summary= (c_proc.communicate()[0]).decode()
        return tcp_conv_summary


# In[2]:


class Iptables:

    def __init__(self, iface):
        self.iface = iface

    def add_ip_port_redirect_entries(self):
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "8", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "10:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "20:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "54:68", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "70:122", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "124:513", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "515:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "9", "-j", "REDIRECT", "--to-port", "9"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "69", "-j", "REDIRECT", "--to-port", "69"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "123", "-j", "REDIRECT", "--to-port", "123"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "514", "-j", "REDIRECT", "--to-port", "514"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "8:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "20", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "22:24", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "26:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "54:78", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "81:109", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "111:112", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "114:442", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "444:464", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "466:989", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "991:994", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "996:6666", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6668:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "21", "-j", "REDIRECT", "--to-port", "21"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "25", "-j", "REDIRECT", "--to-port", "25"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "79", "-j", "REDIRECT", "--to-port", "79"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "110", "-j", "REDIRECT", "--to-port", "110"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "113", "-j", "REDIRECT", "--to-port", "113"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "443"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-port", "465"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "990", "-j", "REDIRECT", "--to-port", "990"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "995", "-j", "REDIRECT", "--to-port", "995"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6667", "-j", "REDIRECT", "--to-port", "6667"])

    def delete_ip_port_redirect_entries(self):
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "8", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "10:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "20:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "54:68", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "70:122", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "124:513", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "515:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "9", "-j", "REDIRECT", "--to-port", "9"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "69", "-j", "REDIRECT", "--to-port", "69"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "123", "-j", "REDIRECT", "--to-port", "123"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "514", "-j", "REDIRECT", "--to-port", "514"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "8:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "20", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "22:24", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "26:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "54:78", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "81:109", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "111:112", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "114:442", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "444:464", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "466:989", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "991:994", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "996:6666", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6668:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "21", "-j", "REDIRECT", "--to-port", "21"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "25", "-j", "REDIRECT", "--to-port", "25"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "79", "-j", "REDIRECT", "--to-port", "79"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "110", "-j", "REDIRECT", "--to-port", "110"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "113", "-j", "REDIRECT", "--to-port", "113"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "443"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-port", "465"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "990", "-j", "REDIRECT", "--to-port", "990"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "995", "-j", "REDIRECT", "--to-port", "995"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6667", "-j", "REDIRECT", "--to-port", "6667"])


    def display_ip_port_redirect_entries(self):
        output = subprocess.check_output(["iptables", "-L", "-t" "nat"])
        print(output)


# In[62]:


# cmd=['VBoxManage','guestcontrol','Ubuntu','run','--exe','home/u/malware/my_test_sample_1','--username','root','--password','1234']
#         #md.extend(args)
# o=subprocess.Popen(cmd)


# In[ ]:





# In[225]:


# capture_filter = r"""evt.type=clone or evt.type=execve or evt.type=chdir or evt.type=open or
# evt.type=creat or evt.type=close or evt.type=socket or evt.type=bind or evt.type=connect or
# evt.type=accept or evt.is_io=true or evt.type=unlink or evt.type=rename or evt.type=brk or
# evt.type=mmap or evt.type=munmap or evt.type=kill or evt.type=pipe"""        
# capture_filter = capture_filter + " " + "and (proc.name=" + 'VirusShare_feb59c32817a5beedf7798ed431c435c' + " " + "or proc.aname=" + 'VirusShare_feb59c32817a5beedf7798ed431c435c' + ")"
# subprocess.Popen(['VBoxManage','guestcontrol','Ubuntu','run','--exe','usr/bin/sysdig','--username','root','--password','1234','--','sysdig/arg0',capture_filter,'-w','/root/logdir/analysis.scap'])


# In[9]:


# strace_filter=strace_filter = r"-etrace=fork,clone,execve,chdir,open,creat,close,socket,connect,accept,bind,read,write,unlink,rename,kill,pipe,dup,dup2"
# c_proc=subprocess.Popen(['VBoxManage','guestcontrol','Ubuntu','run','--exe','/usr/bin/strace','--username','root','--password','1234','--','strace/arg0','-o','/home/u/log/strace_analysis.txt',strace_filter,'-s','64','-eread=all','-ewrite=all','-f','/home/u/malware/VirusShare_feb59c32817a5beedf7798ed431c435c'])


# In[75]:


# c_proc=subprocess.Popen(['VBoxManage','guestcontrol','Ubuntu','run','--exe','usr/bin/ps','--username','root','--password','1234'],stdout=subprocess.PIPE)
# vm_op=(c_proc.communicate()[0]).decode()
# print(vm_op)



# In[45]:


# import re

# p = r"([P]*ID=\d+)"


# c_proc=subprocess.Popen(['VBoxManage','guestcontrol','Ubuntu','list','all'],stdout=subprocess.PIPE)
# vm_op=((c_proc.communicate()[0]).decode())
# print(vm_op)
# pid_sessid = re.findall(p, vm_op)
# pid_sessid_dict={}
# for pid in range(0,len(pid_sessid)-1,2):
#     pid_sessid_dict[(pid_sessid[pid+1][4:len(pid_sessid[pid+1])]).strip()]=(pid_sessid[pid][3:len(pid_sessid[pid])]).strip()
# for k in pid_sessid_dict.keys():
#     print(k,pid_sessid_dict[k])


                        
            


# In[46]:


# # sid='56'
# pid='4774'
# kill_proc=subprocess.check_call(['VBoxManage','guestcontrol','Ubuntu','closeprocess','--session-id',sid,pid])


# In[47]:


#         o=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/chmod','--username',self.u_name,'--password',self.passwd,'chmod/arg0','0777',malware_file])
#         o=subprocess.Popen(['VBoxManage',self.ctrl,self.vm,'run','--exe','/usr/bin/chmod','--username',self.u_name,'--password',self.passwd,'chmod/arg0','+x',malware_file])


# In[71]:


# pid='12333'
# o=subprocess.Popen(['VBoxManage','guestcontrol','Ubuntu','run','--exe','/usr/bin/kill','--username','root','--password','1234','--','kill/arg0','-n','-9',pid])


# In[ ]:




