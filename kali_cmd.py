import paramiko
import sys
import os

def run_ssh_command(host, username, password, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        
        out = stdout.read().decode('utf-8')
        err = stderr.read().decode('utf-8')
        
        if out:
            print(out, end='')
        if err:
            print(err, end='', file=sys.stderr)
            
        exit_status = stdout.channel.recv_exit_status()
        return exit_status
    except Exception as e:
        print(f"SSH Error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()

def upload_file(host, username, password, local_path, remote_path):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username=username, password=password)
        sftp = client.open_sftp()
        # Ensure remote directory exists
        remote_dir = os.path.dirname(remote_path)
        if remote_dir:
            try:
                sftp.stat(remote_dir)
            except FileNotFoundError:
                client.exec_command(f"mkdir -p {remote_dir}")
        
        sftp.put(local_path, remote_path)
        sftp.close()
        print(f"Uploaded {local_path} to {remote_path}")
    except Exception as e:
        print(f"SFTP Error: {e}", file=sys.stderr)
    finally:
        client.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python kali_cmd.py <command>")
        print("       python kali_cmd.py --upload <local_path> <remote_path>")
        sys.exit(1)
    
    host = "192.168.1.11"
    user = "joggyboi"
    pwd = "Ad@251106"
    
    if sys.argv[1] == "--upload" and len(sys.argv) == 4:
        upload_file(host, user, pwd, sys.argv[2], sys.argv[3])
    else:
        command = " ".join(sys.argv[1:])
        sys.exit(run_ssh_command(host, user, pwd, command))
