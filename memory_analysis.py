
import subprocess
import json


class Memory:
    def __init__(self,python_interpreter,voltility_path,memory_dump_path,memory_profile_dir,jsonFormat):
        self.interpreter=python_interpreter
        self.voltility=voltility_path
        self.mem_dump=memory_dump_path
        self.mem_profile=memory_profile_dir
        self.jsonFormat = jsonFormat
    def getMemForensics(self,vol_plugin):
        if self.jsonFormat:
             c_proc=subprocess.Popen([self.interpreter,self.voltility,"-f",self.mem_dump,"-s",self.mem_profile,"-r","json",vol_plugin],stdout=subprocess.PIPE)
        else:    
            c_proc=subprocess.Popen([self.interpreter,self.voltility,"-f",self.mem_dump,"-s",self.mem_profile,vol_plugin],stdout=subprocess.PIPE)
        proc_op=(c_proc.communicate()[0]).decode()
        return proc_op
    def getBanners(self):
        plugin="banners.Banners"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin) 
            banners=proc_op.split("\n")[4:-1]
            offset_and_banners=[]
            for banner in banners:
                offset_and_banners.append(banner.split("\t"))
            return [proc_op,offset_and_banners]
    def getBashHistory(self):
        plugin="linux.bash.Bash"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            bash_history=proc_op.split("\n")[4:-1]
            res_bash_history=[]
            for history in bash_history:
                res_bash_history.append(history.split("\t"))
            return [proc_op,res_bash_history]
    def getCredentialStructureSharing(self):
        plugin="linux.check_creds.Check_creds"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            proc_id=proc_op.split("\n")[4:-1]
            return [proc_op, proc_id]
    def getIdtAltered(self):
        plugin="linux.check_idt.Check_idt"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            idt_altered=proc_op.split("\n")[4:-1]
            idt_altered_symbols=[]
            for idt in idt_altered:
                idt_altered_symbols.append(idt.split("\t"))
            return [proc_op,idt_altered_symbols]
    def getModuleList(self):
        plugin="linux.check_modules.Check_modules"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            module_list=proc_op.split("\n")[4:-1]
            res_module_list=[]
            for module in module_list:
                res_module_list.append(module.split("\t"))
            return [proc_op,res_module_list]
    def getSyscallTable(self):
        plugin="linux.check_syscall.Check_syscall"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            syscall_table=proc_op.split("\n")[4:-1]
            res_syscall_table=[]
            for syscall in syscall_table:
                res_syscall_table.append(syscall.split("\t"))
            return [proc_op,res_syscall_table]
    def getMemoryMappedElf(self):
        plugin="linux.elfs.Elfs"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            memory_mapped_elf=proc_op.split("\n")[4:-1]
            res_memory_mapped_elf=[]
            for elf in memory_mapped_elf:
                res_memory_mapped_elf.append(elf.split("\t"))
            return [proc_op,res_memory_mapped_elf]
    def getProcessesWithEnvVars(self):
        plugin="linux.envvars.Envvars"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            processes_with_env_vars=proc_op.split("\n")[4:-1]
            res_processes_with_env_vars=[]
            for process in processes_with_env_vars:
                res_processes_with_env_vars.append(process.split("\t"))
            return [proc_op,res_processes_with_env_vars]
    def getProcessIoMem(self):
        plugin="linux.iomem.IOMem"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            process_io_mem=proc_op.split("\n")[4:-1]
            res_process_io_mem=[]
            for process in process_io_mem:
                res_process_io_mem.append(process.split("\t"))
            return [proc_op,res_process_io_mem]
    def getKeyboardNotifiers(self):
        plugin="linux.keyboard_notifiers.Keyboard_notifiers"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            keyboard_notifiers=proc_op.split("\n")[4:-1]
            res_keyboard_notifier=[]
            for notifiers in keyboard_notifiers:
                res_keyboard_notifier.append(notifiers.split("\t"))
            return [proc_op,res_keyboard_notifier]
    def getKernelLog(self):
        plugin="linux.kmsg.Kmsg"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            kernel_log=proc_op.split("\n")[4:-1]
            res_kernel_log=[]
            for log in kernel_log:
                res_kernel_log.append(log.split("\t"))
            return [proc_op,res_kernel_log]
    def getLoadedKernelModules(self):
        plugin="linux.lsmod.Lsmod"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            loaded_kernel_modules=proc_op.split("\n")[4:-1]
            res_loaded_kernel_modules=[]
            for kernel_module in loaded_kernel_modules:
                res_loaded_kernel_modules.append(kernel_module.split("\t"))
            return [proc_op,res_loaded_kernel_modules]
    def getMemoryMapsOfProcesses(self):
        plugin="linux.lsof.Lsof"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            memory_maps_of_processes=proc_op.split("\n")[4:-1]
            res_memory_maps_of_processes=[]
            for memory_maps in memory_maps_of_processes:
                res_memory_maps_of_processes.append(memory_maps.split("\t"))
            return [proc_op,res_memory_maps_of_processes]
    def getProcessesWithPotentiallyInjectedCode(self):
        plugin="linux.malfind.Malfind"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            processes_with_potentially_injected_codes=proc_op.split("\n")[4:-1]
            res_processes_with_potentially_injected_codes=[]
            for process in processes_with_potentially_injected_codes:
                res_processes_with_potentially_injected_codes.append(process.split("\t"))
            return [proc_op,res_processes_with_potentially_injected_codes]
    def getProcessesMountSpaces(self):
        plugin="linux.mountinfo.MountInfo"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            processes_mount_spaces=proc_op.split("\n")[4:-1]
            res_processes_mount_spaces=[]
            for process in processes_mount_spaces:
                res_processes_mount_spaces.append(process.split("\t"))
            return [proc_op,res_processes_mount_spaces]
    def getMemoryMapsOfAllProcesses(self):
        plugin="linux.proc.Maps"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            memory_maps=proc_op.split("\n")[4:-1]
            res_memory_maps=[]
            for maps in memory_maps:
                res_memory_maps.append(maps.split("\t"))
            return [proc_op,res_memory_maps]
    def getProcessesWithCommands(self):
        plugin="linux.psaux.PsAux"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            processes_with_commands=proc_op.split("\n")[4:-1]
            res_processes_with_commands=[]
            for processes in processes_with_commands:
                res_processes_with_commands.append(processes.split("\t"))
            return [proc_op,res_processes_with_commands]
    def getAllProcesses(self):
        plugin="linux.pslist.PsList"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            all_processes=proc_op.split("\n")[4:-1]
            res_processes=[]
            for process in all_processes:
                res_processes.append(process.split("\t"))
            return [proc_op,res_processes]
    def getProcessScans(self):
        plugin="linux.psscan.PsScan"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            process_scans=proc_op.split("\n")[4:-1]
            res_process_scans=[]
            for process in process_scans:
                res_process_scans.append(process.split("\t"))
            return [proc_op,res_process_scans]
    def getProcessTree(self):
        plugin="linux.pstree.PsTree"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            process_tree=proc_op.split("\n")[4:-1]
            res_process_tree=[]
            for process in process_tree:
                res_process_tree.append(process.split("\t"))
            return [proc_op,res_process_tree]
    def getNetworkInfoOfAllProcess(self):
        plugin="linux.sockstat.Sockstat"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            network_info=proc_op.split("\n")[4:-1]
            res_network_info=[]
            for process in network_info:
                res_network_info.append(process.split("\t"))
            return [proc_op,res_network_info]
    def getTtyDevices(self):
        plugin="linux.tty_check.tty_check"
        if self.jsonFormat:
            dic = json.loads(self.getMemForensics(plugin))
            return dic
        else:
            proc_op=self.getMemForensics(plugin)
            tty_devices=proc_op.split("\n")[4:-1]
            res_tty_devices=[]
            for device in tty_devices:
                res_tty_devices.append(device.split("\t"))
            return [proc_op,res_tty_devices]
    
