import re

# step 1

def openLogFile(path):
    with open(path) as log_file:
        for log_entry in log_file:
            yield log_entry


log_file = openLogFile("part2.log")
log_entry = next(log_file)
# print("log entry:", log_entry)

# Step 3: Define the logParser function
def logParser(log):
    # log_data = log_entry.split("\t")  # Split the log entry using "\t"
    # print( log_data)
    # print("log_data[1]:", log_data[1])
    # Now you can process log_data as needed

    log_data = re.split("\t", log_entry.rstrip())
    print("log_data:", log_data)
    # print("\n log_data[0]:",log_data[0])
    # r = {}
    
logParser(log_entry)


# import re

# def parseZeekConn(log_entry):
#     log_data = re.split("\t", log_entry.rstrip())
#     print(log_data)
#     r = {}
#     r["ts"] = log_data[0]
#     r["uid"] = log_data[1]
#     r["src_ip"] = log_data[2]
#     r["src_port"] = log_data[3]
#     r["dst_ip"] = log_data[4]
#     r["dst_port"] = log_data[5]
#     r["proto"] = log_data[6]
#     r["service"] = log_data[7]
#     r["duration"] = log_data[8]
#     r["src_bytes"] = log_data[9]
#     r["dst_bytes"] = log_data[10]
#     r["conn_state"] = log_data[11]
#     r["local_src"] = log_data[12]
#     r["local_rsp"] = log_data[13]
#     r["missed_bytes"] = log_data[14]
#     r["history"] = log_data[15]
#     r["srk_pkts"] = log_data[16]
#     r["src_ip_bytes"] = log_data[17]
#     r["dst_pkts"] = log_data[18]
#     r["dst_ip_bytes"] = log_data[19]
#     r["tunnel_parents"] = log_data[20]
#     return r



# log_list = []
# log_list.append(next(log_file))
# print("log_list:", log_list)

# log parser function 

# def logParser(file):
#     log_data = re.split("\t", log_list.rstrip())
#     print("logdata:",log_data)
#     # r = {}
#     # r["ts"] = log_data[0]
#     # return r

# logParser(log_list)

















# step 2
# def parseLogEntry(log_entry):
#     log_data = re.split("\t", log_entry.rstrip())
#     print("parseLogEntry log_data:", log_data)
#     r = {}
#     r["ts"] = log_data[0]
#     r["level"] = log_data[1]
#     r["comp"] = log_data[2]
#     r["content"] = log_data[3]
#     r["rhost"] = log_data[4]
#     return r

# parseLogEntry(demo_log_file)