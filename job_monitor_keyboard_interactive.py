import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import re
import json
from datetime import datetime
import os
import platform

if platform.system() == "Windows":
    from plyer import notification


class HPCJobMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("HPC Job Monitor")
        self.interval = 30
        self.running = False
        self.previous_job_ids = set()
        self.finished_jobs = []
        self.job_info_cache = {}
        self.project_folder_cache = {}

        self.load_jobs_from_json()
        self.create_widgets()

    def create_widgets(self):
        creds_frame = ttk.LabelFrame(self.root, text="HPC SSH Login")
        creds_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(creds_frame, text="Hostname:").grid(row=0, column=0, sticky="e")
        self.host_entry = ttk.Entry(creds_frame, width=30)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2)
        self.host_entry.insert(0, "hostname") # Add your hostname in the quotes here.

        ttk.Label(creds_frame, text="Username:").grid(row=1, column=0, sticky="e")
        self.user_entry = ttk.Entry(creds_frame, width=30)
        self.user_entry.grid(row=1, column=1, padx=5, pady=2)
        self.user_entry.insert(0, "username") # Add your username in the quotes here.

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

        clear_button = ttk.Button(interval_frame, text="Clear History", command=self.clear_history)
        clear_button.pack(side="right")

        self.last_updated_label = ttk.Label(self.root, text="Last Updated: N/A")
        self.last_updated_label.pack(pady=(0, 10))

        columns = ("Job ID", "Project Folder", "Comment", "Job Name", "Class", "Status")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=140, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(self.root, text="Finished Jobs").pack(pady=(10, 0))
        self.finished_tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.finished_tree.heading(col, text=col)
            self.finished_tree.column(col, width=140, anchor="center")
        self.finished_tree.pack(fill="both", expand=True, padx=10, pady=5)

        style = ttk.Style(self.root)
        self.color_running = "#00AA00"
        self.color_queued = "#FFAA00"
        self.color_other = "#CC3300"
        self.color_finished = "#5599FF"

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
            if interval < 5:
                messagebox.showerror("Error", "Interval should be at least 5 seconds.")
                return
            self.interval = interval
        except ValueError:
            messagebox.showerror("Error", "Invalid interval value.")
            return

        if not self.user_entry.get() or not self.host_entry.get():
            messagebox.showerror("Error", "Please enter hostname and username.")
            return

        self.running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.save_jobs_to_json()

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all job history?"):
            for f in ["current_jobs.json", "finished_jobs.json"]:
                try:
                    os.remove(f)
                except:
                    pass
            self.finished_jobs.clear()
            self.previous_job_ids.clear()
            self.update_tree([])

    def run_ssh_command(self, remote_command):
        user = self.user_entry.get()
        host = self.host_entry.get()
        password = self.pass_entry.get()

        full_cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{user}@{host}", f"bash -l -c \"{remote_command}\""
        ]

        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise Exception(result.stderr.strip())
            return result.stdout
        except Exception as e:
            raise Exception(f"SSH command failed: {e}")

    def run_qstat(self):
        return self.run_ssh_command("qstat")

    def get_project_folder(self, job_id):
        if job_id in self.project_folder_cache:
            return self.project_folder_cache[job_id]

        output = self.run_ssh_command(f"qstat -f {job_id}")
        match = re.search(r'PBS_O_WORKDIR=(.*)', output)
        if match:
            folder = match.group(1).strip()
            username = self.user_entry.get().strip()
            prefix = f"/rds/general/user/{username}/"
            if folder.startswith(prefix):
                folder = folder[len(prefix):]
            folder = folder.rstrip(",")
            self.project_folder_cache[job_id] = folder
            return folder
        return "Unknown"

    def parse_qstat(self, output):
        lines = output.strip().splitlines()
        jobs = []
        if len(lines) < 3:
            return jobs
        for line in lines[2:]:
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) < 5:
                continue
            job_id, job_class, job_name, status = parts[:4]
            comment = " ".join(parts[4:])
            project_folder = self.get_project_folder(job_id)
            jobs.append({
                "Job ID": job_id,
                "Class": job_class,
                "Job Name": job_name,
                "Status": status,
                "Comment": comment,
                "Project Folder": project_folder
            })
        return jobs

    def notify_job_finished(self, job):
        message = f"Job {job.get('Job ID', '')} finished ({job.get('Job Name', '')})"
        if platform.system() == "Darwin":
            subprocess.call(['osascript', '-e', f'display notification "{message}" with title "HPC Job Monitor"'])
        elif platform.system() == "Windows":
            notification.notify(title="HPC Job Monitor", message=message, timeout=5)

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
        now = datetime.now()

        for finished_id in newly_finished_ids:
            if finished_id not in [fj["Job ID"] for fj in self.finished_jobs]:
                finished_job = self.job_info_cache.get(finished_id)
                if finished_job:
                    finished_job = finished_job.copy()
                    finished_job["Status"] = "Finished"
                    old_comment = finished_job.get("Comment", "").strip().lower()
                    finished_time_str = now.strftime('%Y-%m-%d %H:%M')
                    if "seconds" in old_comment:
                        finished_job["Comment"] = f"Completed {finished_time_str}"
                    else:
                        finished_job["Comment"] = f"Recorded Finished {finished_time_str}"
                    self.finished_jobs.append(finished_job)
                    self.notify_job_finished(finished_job)
        self.finished_jobs = [fj for fj in self.finished_jobs if fj["Job ID"] not in current_job_ids]
        self.previous_job_ids = current_job_ids

        def gui_update():
            self.tree.delete(*self.tree.get_children())
            for job in jobs:
                color = color_for_status(job.get("Status", ""))
                self.tree.insert("", "end", values=(
                    job.get("Job ID", ""),
                    job.get("Project Folder", "Unknown"),
                    job.get("Comment", ""),
                    job.get("Job Name", ""),
                    job.get("Class", ""),
                    job.get("Status", "")
                ), tags=(color,))

            self.finished_tree.delete(*self.finished_tree.get_children())
            for job in self.finished_jobs:
                color = color_for_status(job.get("Status", ""), finished=True)
                self.finished_tree.insert("", "end", values=(
                    job.get("Job ID", ""),
                    job.get("Project Folder", "Unknown"),
                    job.get("Comment", ""),
                    job.get("Job Name", ""),
                    job.get("Class", ""),
                    job.get("Status", "")
                ), tags=(color,))

            self.last_updated_label.config(text=f"Last Updated: {datetime.now().strftime('%H:%M:%S')}")

        self.root.after(0, gui_update)

    def monitor_loop(self):
        while self.running:
            start_time = time.time()
            try:
                output = self.run_qstat()
                jobs = self.parse_qstat(output)
                self.update_tree(jobs)
            except Exception as e:
                self.show_error(f"Error: {e}")
                self.stop_monitoring()
                return
            time.sleep(max(0, self.interval - (time.time() - start_time)))

    def show_error(self, message):
        def show():
            messagebox.showerror("Error", message)
        self.root.after(0, show)

    def save_jobs_to_json(self):
        with open("current_jobs.json", "w") as f:
            json.dump(list(self.job_info_cache.values()), f, indent=2)
        with open("finished_jobs.json", "w") as f:
            json.dump(self.finished_jobs, f, indent=2)

    def load_jobs_from_json(self):
        if os.path.exists("finished_jobs.json"):
            with open("finished_jobs.json") as f:
                self.finished_jobs = json.load(f)
        if os.path.exists("current_jobs.json"):
            with open("current_jobs.json") as f:
                old_jobs = json.load(f)
                self.previous_job_ids = set(job["Job ID"] for job in old_jobs)
                for job in old_jobs:
                    self.job_info_cache[job["Job ID"]] = job


if __name__ == "__main__":
    root = tk.Tk()
    app = HPCJobMonitor(root)
    root.mainloop()
