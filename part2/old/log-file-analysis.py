import re


def openLogFile(path):
    with open(path) as log_file:
        for log_entry in log_file:
            yield log_entry

def parseZeekConn(log_entry):
    log_data = re.split("\t", log_entry_entry.rstrip())
    r = {}
    r["ts"] = log_data[0]
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    return r


