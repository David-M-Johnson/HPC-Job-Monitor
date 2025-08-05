# HPC-Job-Monitor

A Python GUI application to monitor HPC cluster jobs via SSH. Originally written for Imperial College London's cluster, and will require adaptation for other HPCs.

This tool connects to a remote HPC login node and periodically checks job statuses with 'qstat' and 'qstat -f'. It displays active and finished jobs in an easy-to-read, color-coded interface. There are two version. The basic version, using Paramiko, and another version using an sshpass, which you will need if your HPC perfents authentication with Paramiko.

---

## Features

- Connects to HPC clusters using SSH (via [Paramiko](https://github.com/paramiko/paramiko)) or [sshpass](https://linux.die.net/man/1/sshpass#:~:text=sshpass%20is%20a%20utility%20designed,by%20an%20interactive%20keyboard%20user/.)
- Periodically updates job status with customizable interval (no faster than 30 seconds)
- Displays active jobs with color-coded statuses:
  - **Green**: Running jobs
  - **Orange**: Queued jobs
  - **Red**: Other statuses
  - **Blue**: Finished Jobs
- The program will also store a 'history' of ongoing and finished jobs. This way, if the program terminates and restarts, it can pick up from where it left off; however, the program must at some point run while the job is active, otherwise it will never show up in the 'finished' jobs table.

---

## Requirements

- Python 3.6+
- Paramiko or sshpass
- Tkinter

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/David-M-Johnson/HPC-Job-Monitor.git
   cd HPC-Job-Monitor

## How to Use
Note: job_monitor_local.py uses Paramiko and is slightly better, but for some HPCs, you will need to use sshpass, which is the other python file.

### Edit a few things in job_monitor_local.py or job_monitor_keyboard_interactive.py.
1. See comments with the word "edit." Add your username and hostname in the proper places. If you typically SSH into your HPC with 'ssh username@hostname', put 'hostname' and 'username'.
2. On the Imperial College HPC, the status of jobs is checked with 'qstat.' This may vary. Determine how to check job status on the HPC you are using. Search for all 7 instances of 'qstat' in job_monitor_local.py. Replace them all with your command. If necessary (very likely), change the way parsing is done based on what your queue status checker returns. The current program also runs 'qstat -f' to get the run folder. I wrote this to trim everything before username, but you may change this.
4. Similarly, you may need to change the logic for status coloring.

### Run program locally
1. After getting job_monitor_local.py and the two .json files on your local computer, navigate to their directory in the command line.
2. Run the program with 'python job_monitor_local.py'
3. Note: Definitely do not put in a backdoor and send this to the IT team for widespread distribution.

### Other Notes
1. Note that the first update could take a minute because the program needs to SSH into a login node of your HPC. This is the most finicky part of the program. If you find any good solutions, please let me know!
2. If you submit a job and it crashes before an update, it will not be shown in the "finished jobs" section.
3. Your HPC may how firewalls or something to prevent you from doing ssh.connect() the way that I have done. You may have to find a work around.
4. This program essentially "sits" on a login node. For very busy HPCs or ones that are closely monitored for irregular activity ... you might get a talking to.
