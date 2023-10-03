import re
import datetime
import matplotlib.pyplot as plt
from collections import Counter

# Step 1: Open the log file and process one line at a time
def openLogFile(path):
    with open(path) as log_file:
        for log_entry in log_file:
            yield log_entry

# Initialize a count for the total number of entries
# total_entries_count = 0

# Step 2: Create a list to store log entries as dictionaries
log_entries = []

# Step 3: Create a datetime object to record the date
current_time = datetime.datetime.now()
current_time_str = current_time.strftime("%b %d %H:%M:%S")

print("\nprogram start time:", current_time_str, "\n")

# Step 4: Read and parse log entries into dictionaries
path = "part2.log"
log_file = openLogFile(path)

for log_entry in log_file:
    # total_entries_count += 1  # Increment the count for each entry

    # Define regex pattern to extract log entry fields
    pattern = r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\w+) (\w+)\((\w+)\)\[(\d+)\]: (.+)'

    # Use re.match to extract fields from the log entry
    match = re.match(pattern, log_entry)

    if match:
        timestamp, hostname, process, action, pid, message = match.groups()
        log_entry_dict = {
            "original_timestamp": timestamp,
            "current_timestamp": current_time_str,
            "hostname": hostname,
            "process": process,
            "action": action,
            "pid": pid,
            "message": message
        }
        log_entries.append(log_entry_dict)

# Step 5: Count the occurrences of 'process' components
process_counter = Counter(entry['process'] for entry in log_entries)

# Step 6: Find the top 3 most common 'process' components
top_3_processes = process_counter.most_common(3)

# Step 7: Print analysis results
print("\n\nLOG FILE ANALYZER\n\n")
print(f"For filename: {path}")
# print("Total number of entries:", total_entries_count,"\n")
print("Top 3 most common components:")
for process, count in top_3_processes:
    print(f"Component: {process}, Count: {count}")


# Step 8: Create and display the plot
def classify_time(timestamp):
    hour = timestamp.hour
    if 9 <= hour <= 17:
        return "Working Hours"
    else:
        return "After Hours"

def plot_process_usage(log_entries):
    process_counter = Counter(entry['process'] for entry in log_entries)
    working_hours_counter = Counter()
    after_hours_counter = Counter()

    for entry in log_entries:
        timestamp = datetime.datetime.strptime(entry["original_timestamp"], "%b %d %H:%M:%S")
        time_category = classify_time(timestamp)
        process = entry["process"]

        if time_category == "Working Hours":
            working_hours_counter.update([process])
        else:
            after_hours_counter.update([process])

    # Get the top 3 most common processes
    top_3_processes = process_counter.most_common(3)

    # Create the plots
    plt.figure(figsize=(12, 6))

    # for i, (process, count) in enumerate(top_3_processes, 1):
    #     plt.subplot(3, 1, i)
    #     plt.bar([f"{process} - Working Hours (9-5pm)", f"{process} - After Hours"], [working_hours_counter[process], after_hours_counter[process]])
    #     plt.title(f"Usage of {process} component during Working Hours and After Hours")

    for i, (process, count) in enumerate(top_3_processes, 1):
        plt.subplot(3, 1, i)
        plt.bar([f"{process} - Working Hours (9am-5pm) - Count: {working_hours_counter[process]}", f"{process} - After Hours - Count: {after_hours_counter[process]}"], [working_hours_counter[process], after_hours_counter[process]])
        plt.title(f"Usage of {process} component during Working Hours (9am-5pm) and After Hours")

plt.tight_layout()
plt.show()

# Call the function to create and display the plot
plot_process_usage(log_entries)