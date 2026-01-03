import tkinter as tk
from tkinter import filedialog, messagebox
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# ---------------- CONFIG ----------------
WHITELIST = ["127.0.0.1"]   # Ignore trusted IPs
TIME_WINDOW_MIN = 2         # Time window (minutes)

# ---------------- CORE ANALYSIS ----------------
def analyze_log(log_file, threshold):
    records = []

    with open(log_file, "r") as f:
        for line in f:
            parts = line.split()

            # Apache/Nginx access log minimum length
            if len(parts) < 9:
                continue

            ip = parts[0]
            status = parts[7]

            if ip in WHITELIST:
                continue

            # Detect failed login
            if status == "401":
                time_str = parts[3].strip("[")
                try:
                    timestamp = datetime.strptime(
                        time_str, "%d/%b/%Y:%H:%M:%S"
                    )
                except:
                    continue

                records.append([ip, timestamp])

    if not records:
        return {}, None

    df = pd.DataFrame(records, columns=["IP", "Time"])

    # -------- Time-window detection (Feature 4) --------
    alerts = {}
    for ip in df["IP"].unique():
        times = df[df["IP"] == ip]["Time"].sort_values()
        for i in range(len(times)):
            count = sum(
                (times >= times.iloc[i]) &
                (times <= times.iloc[i] + pd.Timedelta(minutes=TIME_WINDOW_MIN))
            )
            if count >= threshold:
                alerts[ip] = count
                break

    return alerts, df

# ---------------- REPORT ----------------
def generate_report(alerts):
    with open("incident_report.txt", "w") as f:
        f.write("LOG FILE INTRUSION REPORT\n")
        f.write("==========================\n\n")
        for ip, count in alerts.items():
            f.write(f"IP Address : {ip}\n")
            f.write(f"Attempts   : {count}\n")
            f.write("Severity   : HIGH\n\n")

# ---------------- GRAPH ----------------
def generate_graph(alerts):
    if not alerts:
        return

    plt.figure()
    plt.bar(alerts.keys(), alerts.values())
    plt.xlabel("IP Address")
    plt.ylabel("Failed Attempts")
    plt.title("Brute Force Attempts")
    plt.tight_layout()
    plt.savefig("traffic_graph.png")
    plt.show()

# ---------------- GUI ACTION ----------------
def run_analysis():
    if not log_path.get():
        messagebox.showerror("Error", "Please select a log file")
        return

    try:
        threshold = int(threshold_entry.get())
    except:
        messagebox.showerror("Error", "Threshold must be a number")
        return

    alerts, df = analyze_log(log_path.get(), threshold)

    output.delete(1.0, tk.END)

    if not alerts:
        output.insert(tk.END, "System clean. No intrusion detected.\n")
        return

    generate_report(alerts)
    generate_graph(alerts)

    for ip, count in alerts.items():
        output.insert(
            tk.END,
            f"[ALERT] Brute Force Detected\nIP: {ip}\nAttempts: {count}\n\n"
        )

# ---------------- FILE PICKER ----------------
def browse_file():
    file = filedialog.askopenfilename(
        filetypes=[("Log files", "*.log"), ("All files", "*.*")]
    )
    log_path.set(file)

# ---------------- GUI ----------------
root = tk.Tk()
root.title("Log File Intrusion Detection System")
root.geometry("600x500")

log_path = tk.StringVar()

tk.Label(root, text="Select Log File").pack()
tk.Entry(root, textvariable=log_path, width=60).pack()
tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

tk.Label(root, text="Failed Attempt Threshold").pack()
threshold_entry = tk.Entry(root)
threshold_entry.pack()
threshold_entry.insert(0, "3")

tk.Button(root, text="Run Analysis", command=run_analysis).pack(pady=10)

output = tk.Text(root, height=15)
output.pack()

root.mainloop()