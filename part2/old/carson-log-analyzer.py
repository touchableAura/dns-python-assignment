import re 
from datetime import datetime as dt
from collections import Counter 

print("\nStep 1: load a single line into memory from log file\n")

def openLogFile(path):
    with open(path) as log_file:
        for log_entry in log_file:
            yield log_entry

log_file = openLogFile("part2.log")
# print(type(log_file)) # prints: class 'generator'
print(next(log_file))

# step 2: parse the log file and record the fields
# Month Day H:M:S Level Component[ProcessID]: Content

def parseZeekConn(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    print("logdata:",log_data)
    r = {}
    r["ts"] = log_data[0]
    return r

parseZeekConn("part2.log")

# Step 3:datetime object to interpret timestamp


# Find and print the three most commonly used components 


# Create a plot







