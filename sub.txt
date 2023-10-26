import subprocess

# Define a list of IP ranges to trace
ip_ranges = [
    #("10.2.0.0", "10.2.255.255"),
    #("10.3.0.0", "10.3.255.255"),
    ("10.5.0.0", "10.5.255.255"),
        ("10.6.0.0", "10.6.255.255"),
            ("10.7.0.0", "10.7.255.255"),
                ("10.8.0.0", "10.8.255.255"),
                    ("10.9.0.0", "10.9.255.255"),
                        ("10.10.0.0", "10.10.255.255"),
    # Add more IP ranges as needed
]

# Loop through the IP ranges and call your original program for each range
for start_ip, end_ip in ip_ranges:
    try:
        subprocess.run(["python3", "topology-tracing.py", start_ip, end_ip], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running traceroute for IP range {start_ip} - {end_ip}: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
