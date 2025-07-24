# HPC-Job-Monitor

A simple Python GUI application to monitor HPC cluster jobs via SSH.  
This tool connects to a remote HPC login node and periodically fetchs job statuses. It displays active and finished jobs in an easy-to-read, color-coded interface.

---

## Features

- Connects to HPC clusters using SSH (via [Paramiko](https://github.com/paramiko/paramiko))
- Periodically updates job status with customizable interval (no faster than 15 seconds)
- Displays active jobs with color-coded statuses:
  - **Green**: Running jobs
  - **Orange**: Queued jobs
  - **Red**: Other statuses
- Maintains a separate list of finished jobs (displaying Job ID, Class, Job Name, and Status)
- Finished jobs show a lighter blue color for better visibility on dark backgrounds
- Simple and clean Tkinter GUI interface

---

## Requirements

- Python 3.6+
- [Paramiko](https://pypi.org/project/paramiko/)
- Tkinter (usually included with standard Python installations)

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/David-M-Johnson/HPC-Job-Monitor.git
   cd HPC-Job-Monitor

## How to Use

### Edit a few things in job_monitor_local.py.
1. See comments for "Put your host name here" and "Put your user name here." If you typically SSH into your HPC with 'ssh username@hostname', put 'hostname' and 'username'
2. On my HPC, the status of jobs is checked with 'qstat.' Determine what for the HPC you are using. Search for all 7 instances of 'qstat' in job_monitor_local.py. Replace them all with your command.

### Run program locally
1. After getting job_monitor_local.py to a convenient location on your local computer, navigate to its directory in command line interface.
2. Run the program with 'python job_monitor_local.py'
3. Note that the first update could take a minute or two because the program needs to SSH into a login node of your HPC.
