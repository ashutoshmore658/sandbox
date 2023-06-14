import os
import subprocess
import time

dire="/home/ashutoshreddy/malwares/"

for malfile in os.listdir(dire):
    mal=dire + malfile
    c_proc=subprocess.Popen(["python3","/home/ashutoshreddy/jupyter/sandbox/sandbox.py",mal,"-v","-f","-M","-t","40"])
    time.sleep(600)
