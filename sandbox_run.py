import os
import subprocess
import time

dire="/home/ashutoshreddy/malwares/"

for malfile in os.listdir(dire):
    mal=dire + malfile
    c_proc=subprocess.Popen(["python3","/home/ashutoshreddy/jupyter/sandbox/sandbox.py",mal,"-f","-M","-t","30"])
    time.sleep(540)