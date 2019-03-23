import pysftp
import paramiko
import os.path

def cpy_pub_serv(ip, username, ssh_pass, remote_ssh_folder, pub_key, remote_auth_file):

    cnopts = pysftp.CnOpts()
    cnopts.hostkeys = None

    # connect SFTP

    try:
        srv = pysftp.Connection(host=ip, username=username, password=ssh_pass, cnopts=cnopts)

    except pysftp.AuthenticationException:
        return -1

    ret = srv.isdir(remote_ssh_folder)

    if not ret:
        srv.mkdir(remote_ssh_folder)

    # srv.rename(remote_auth_file, remote_auth_renamed)
    srv.put(pub_key, remote_auth_file)
    print "[+] Public key copied to " + ip

    # Close SFTP
    srv.close()


def conn_ssh(ip, username, ssh_pass, remote_cmd):
    s = paramiko.SSHClient()
    s.load_system_host_keys()
    s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    s.connect(ip, 22, username, ssh_pass)
    stdin, stdout, stderr = s.exec_command(remote_cmd)
    print stdout.read()
    s.close()

def vrfy_files(pub_key, ip_list):

    if os.path.isfile(pub_key) == False or os.path.isfile(ip_list) == False:
        ret = -1

    else:
        ret = 0

    return ret

def chk_argv():
    pass


def main():
    serv_lst = "/you/path/ips.lst"  # File with IPs
    pub_key = "/you/path/.ssh/id_rsa.pub"  # File public keyfile

    status_files = vrfy_files(pub_key, serv_lst)


    if status_files != 0:
        print "[!] Verify " + pub_key + " and " + serv_lst + " EXIST"
        exit(-1)


    remote_cmd = "sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config; systemctl restart sshd"
    #remote_cmd = "ls -la"
    remote_user_ssh = "root"
    ssh_pass = "hola"

    remote_user_home = "/" + remote_user_ssh + "/"
    #remote_user_home = "/home/" + remote_user_ssh + "/"

    remote_ssh_folder = remote_user_home + ".ssh/"
    remote_auth_file = remote_ssh_folder + "authorized_keys"
    remote_auth_renamed = remote_ssh_folder + "authorized_keys.old"

    # Open IP file
    with open(serv_lst, "r") as f:
        text = f.readlines()

    # for-loop for IP list
    for lineHost in text:

        # Remove CRLF
        lineHost = lineHost.replace("\n", "")

        # Connect SFTP

        ret = cpy_pub_serv(lineHost, remote_user_ssh, ssh_pass, remote_ssh_folder, pub_key, remote_auth_file)

        if ret == -1:
            print "[!] Auth FAIL, please check user/password for " + lineHost
            exit(-10)

        # Connect SSH
        conn_ssh(lineHost, remote_user_ssh, ssh_pass, remote_cmd)

        print "bye"

main()