import os
import subprocess
import time

dire="/home/ashutoshreddy/malwares/"

for malfile in os.listdir(dire):
	mal=dire + malfile
	c_proc=subprocess.Popen(["python3","/home/ashutoshreddy/sandbox/sandbox.py",mal,"-t","15"])
	time.sleep(120)
	
