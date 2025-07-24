import tkinter as tk
from tkinter import ttk, messagebox
import paramiko
import threading
import time
import re
from datetime import datetime

class HPCJobMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("HPC Job Monitor")
        self.interval = 30  # default in seconds
        self.running = False
        self.ssh = None
        self.previous_job_ids = set()
        self.finished_jobs = []
        self.job_info_cache = {}

        self.create_widgets()

    def create_widgets(self):
        creds_frame = ttk.LabelFrame(self.root, text="HPC SSH Login")
        creds_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(creds_frame, text="Hostname:").grid(row=0, column=0, sticky="e")
        self.host_entry = ttk.Entry(creds_frame, width=30)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2)
        self.host_entry.insert(0, "host-name") # Put your host name here

        ttk.Label(creds_frame, text="Username:").grid(row=1, column=0, sticky="e")
        self.user_entry = ttk.Entry(creds_frame, width=30)
        self.user_entry.grid(row=1, column=1, padx=5, pady=2)
        self.user_entry.insert(0, "user-name") # Put your user name here

        ttk.Label(creds_frame, text="Password:").grid(row=2, column=0, sticky="e")
        self.pass_entry = ttk.Entry(creds_frame, width=30, show="*")
        self.pass_entry.grid(row=2, column=1, padx=5, pady=2)

        interval_frame = ttk.Frame(self.root)
        interval_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(interval_frame, text="Update interval (sec):").pack(side="left")
        self.interval_var = tk.StringVar(value=str(self.interval))
        self.interval_entry = ttk.Entry(interval_frame, width=5, textvariable=self.interval_var)
        self.interval_entry.pack(side="left", padx=5)

        self.start_button = ttk.Button(interval_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side="left", padx=10)

        self.stop_button = ttk.Button(interval_frame, text="Stop", command=self.stop_monitoring, state="disabled")
        self.stop_button.pack(side="left")

        # Last updated label
        self.last_updated_label = ttk.Label(self.root, text="Last Updated: N/A")
        self.last_updated_label.pack(pady=(0, 10))

        # Treeview for active jobs
        columns = ("Job ID", "Class", "Job Name", "Status", "Comment")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(self.root, text="Finished Jobs").pack(pady=(10, 0))
        self.finished_tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.finished_tree.heading(col, text=col)
            self.finished_tree.column(col, width=120, anchor="center")
        self.finished_tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Setup styles for colors and backgrounds properly
        style = ttk.Style(self.root)

        self.color_running = "#00AA00"  # green
        self.color_queued = "#FFAA00"   # yellow/orange
        self.color_other = "#CC3300"    # red
        self.color_finished = "#5599FF" # lighter blue for finished

        self.tree.tag_configure("green", foreground=self.color_running)
        self.tree.tag_configure("orange", foreground=self.color_queued)
        self.tree.tag_configure("red", foreground=self.color_other)
        self.finished_tree.tag_configure("blue", foreground=self.color_finished)

        style.configure("Treeview",
                        background="black",
                        fieldbackground="black",
                        foreground="white",
                        font=('TkDefaultFont', 10))
        style.map("Treeview",
                  background=[('selected', '#0044AA')],
                  foreground=[('selected', 'white')])

    def start_monitoring(self):
        try:
            interval = int(self.interval_var.get())
            if interval < 15:
                messagebox.showerror("Error", "Interval should be at least 5 seconds.")
                return
            self.interval = interval
        except ValueError:
            messagebox.showerror("Error", "Invalid interval value.")
            return

        if not self.user_entry.get() or not self.host_entry.get():
            messagebox.showerror("Error", "Please enter hostname and username.")
            return

        try:
            self.create_ssh_session()
        except Exception as e:
            messagebox.showerror("SSH Error", f"Could not establish SSH connection:\n{e}")
            return

        self.running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.running = False
        if self.ssh:
            self.ssh.close()
            self.ssh = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def create_ssh_session(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(
            self.host_entry.get(),
            username=self.user_entry.get(),
            password=self.pass_entry.get(),
            allow_agent=False,
            look_for_keys=False,
            timeout=30
        )

    def run_qstat(self):
        if self.ssh is None:
            raise Exception("SSH session not established")

        stdin, stdout, stderr = self.ssh.exec_command('bash -l -c "qstat"') # Change "qstat"
        output = stdout.read().decode()
        error = stderr.read().decode()
        if error.strip():
            raise Exception(f"Error output from qstat: {error.strip()}")
        return output if output is not None else ""

    def parse_qstat(self, output):
        lines = output.strip().splitlines()
        jobs = []
        if len(lines) < 3:
            return jobs

        for line in lines[2:]:
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) < 5:
                continue  # Malformed line

            job_id, job_class, job_name, status = parts[:4]
            comment = " ".join(parts[4:]) 

            jobs.append({
                "Job ID": job_id,
                "Class": job_class,
                "Job Name": job_name,
                "Status": status,
                "Comment": comment
            })

        return jobs

    def update_tree(self, jobs):
        def color_for_status(status, finished=False):
            s = status.lower()
            if finished:
                return "blue"
            if "running" in s:
                return "green"
            elif "queued" in s:
                return "orange"
            else:
                return "red"

        current_job_ids = set(job["Job ID"] for job in jobs)

        for job in jobs:
            self.job_info_cache[job["Job ID"]] = job.copy()

        newly_finished_ids = self.previous_job_ids - current_job_ids

        for finished_id in newly_finished_ids:
            if finished_id not in [fj["Job ID"] for fj in self.finished_jobs]:
                finished_job = self.job_info_cache.get(finished_id)
                if finished_job is None:
                    finished_job = {
                        "Job ID": finished_id,
                        "Class": "",
                        "Job Name": "",
                        "Status": "Finished",
                        "Comment": ""
                    }
                else:
                    finished_job = finished_job.copy()
                    finished_job["Status"] = "Finished"
                    finished_job["Comment"] = ""
                self.finished_jobs.append(finished_job)

        # Remove finished jobs that reappear in active jobs
        self.finished_jobs = [fj for fj in self.finished_jobs if fj["Job ID"] not in current_job_ids]

        self.previous_job_ids = current_job_ids

        def gui_update():
            self.tree.delete(*self.tree.get_children())
            for job in jobs:
                color = color_for_status(job["Status"], finished=False)
                self.tree.insert("", "end", values=(
                    job["Job ID"], job["Class"], job["Job Name"], job["Status"], job["Comment"]), tags=(color,))

            self.finished_tree.delete(*self.finished_tree.get_children())
            for job in self.finished_jobs:
                color = color_for_status(job["Status"], finished=True)
                self.finished_tree.insert("", "end", values=(
                    job["Job ID"], job["Class"], job["Job Name"], job["Status"], job["Comment"]), tags=(color,))

            self.last_updated_label.config(text=f"Last Updated: {datetime.now().strftime('%H:%M:%S')}")

        self.root.after(0, gui_update)



    def monitor_loop(self):
        while self.running:
            start_time = time.time()
            try:
                output = self.run_qstat()
                if not output:
                    raise Exception("Empty output from qstat")
                jobs = self.parse_qstat(output)
                self.update_tree(jobs)
            except Exception as e:
                self.show_error(f"Error: {e}")
                self.stop_monitoring()
                return
            elapsed = time.time() - start_time
            time_to_sleep = self.interval - elapsed
            if time_to_sleep > 0:
                time.sleep(time_to_sleep)

    def show_error(self, message):
        def show():
            messagebox.showerror("Error", message)
        self.root.after(0, show)

if __name__ == "__main__":
    root = tk.Tk()
    app = HPCJobMonitor(root)
    root.mainloop()
