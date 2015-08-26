package main

import "fmt"
import "sync"
import "os"
import "bytes"
import "os/exec"
import "regexp"
import "log"
import "strconv"
import "io/ioutil"

// In this folder we will store all results of our work
var target_directory = ""
var public_key_path = "/root/.ssh/id_rsa.pub"
var container_private_path = "/vz_zram/private"

/*

Download all images
vztmpl-dl --update centos-6-x86_64 centos-6-x86 centos-7-x86_64 debian-7.0-x86 debian-7.0-x86_64 debian-8.0-x86_64 ubuntu-12.04-x86 ubuntu-12.04-x86_64 ubuntu-14.04-x86 ubuntu-14.04-x86_64 debian-6.0-x86_64

Please configure NAT before:

Fix /etc/modprobe.d/openvz.conf to following content:
options nf_conntrack ip_conntrack_disable_ve0=0
vim /etc/sysct.conf

Uncomment:
net.ipv4.ip_forward=1
sysctl -p
iptables -t nat -A POSTROUTING -s 10.10.10.1/24 -o eth0 -j SNAT --to 192.168.0.241

Save iptables config
/etc/init.d/iptables save

Enable iptables:
chkconfig iptables on

Generate ssh key:
ssh-keygen -t rsa -q -f /root/.ssh/id_rsa -P ""

Disable quotas:

vim /etc/vz/vz.conf

# Disable quota
DISK_QUOTA=no

Create zram disk for build speedup:
modprobe zram num_devices=1
echo $((20*1024*1024*1024)) > /sys/block/zram0/disksize
mkdir /vz_zram
mkfs.ext4 /dev/zram0 
mount /dev/zram0 /vz_zram
mkdir /vz_zram/private

*/

/*
For renaming of result packages you could use:
find -type f| perl -e 'do{ chomp; my @m=split "/", $_; my @n = split /\./, $_; rename($_, "fastnetmon-git-447aa5b86bb5a248e310c15a4d5945e72594d6cf-$m[1]_x86_64.$n[-1]"); } for <>' 
*/

var distros_x86_64 = []string{ "centos-6-x86_64", "centos-7-x86_64", "debian-6.0-x86_64", "debian-7.0-x86_64", "debian-8.0-x86_64", "ubuntu-12.04-x86_64", "ubuntu-14.04-x86_64" } 

var distros_x86 = []string{ "centos-6-x86", "debian-6.0-x86", "debian-7.0-x86", "ubuntu-12.04-x86", "ubuntu-14.04-x86" }

var start_ctid_number = 1000

func main() {
    target_directory, err := ioutil.TempDir("/root", "builded_packages") 
 
    if err != nil {
        log.Fatal("Can't create temp folder", err)
    }

    fmt.Println("We will store result data to folder", target_directory)
 
    _ = distros_x86
    var wg sync.WaitGroup

    if _, err := os.Stat(public_key_path); os.IsNotExist(err) {
        log.Fatal("Please generate ssh keys for root here")
    }

    for element_number, distro := range distros_x86_64 {
        // Increment the WaitGroup counter.
        wg.Add(1)

        go func(position int, distribution_name string) {
            // Decrement the counter when the goroutine completes. 
            defer wg.Done()

            ip_address := fmt.Sprintf("10.10.10.%d", position)
            ctid := start_ctid_number + position
            ctid_as_string := strconv.Itoa(ctid)

            vzctl_create_as_string := fmt.Sprintf("create %d --ostemplate %s --config vswap-4g --layout simfs --ipadd %s --diskspace 20G --hostname ct%d.test.com --private %s/%d", ctid, distribution_name, ip_address, ctid, container_private_path, ctid)

            r := regexp.MustCompile("[^\\s]+")
            vzctl_create_as_list := r.FindAllString(vzctl_create_as_string, -1) 

            fmt.Println("Create container ", ctid_as_string)
            create_cmd := exec.Command("/usr/sbin/vzctl", vzctl_create_as_list...)
            //cmd.Stdout = os.Stdout
            //cmd.Stderr = os.Stderr
            err := create_cmd.Run()

            if err != nil {
                log.Println("create failed")
                log.Fatal(err)
            }

            // Run it
            fmt.Println("Start container ", ctid_as_string)
            // We whould wait here for full CT startup
            start_cmd := exec.Command("/usr/sbin/vzctl", "start", ctid_as_string, "--wait");
            // start_cmd.Stdout = os.Stdout
            // start_cmd.Stderr = os.Stderr
            err = start_cmd.Run()           

            if err != nil {
                log.Println("start failed")
                log.Fatal(err)
            }

            vzroot_path := fmt.Sprintf("/vz/root/%d", ctid)
            auth_keys_path := vzroot_path + "/root/.ssh/authorized_keys" 

            os.Mkdir(vzroot_path + "/root/.ssh", 0600)
            copy_key_command := exec.Command("cp", public_key_path, auth_keys_path)
            copy_key_command.Run()

            if err != nil {
                log.Println("Can't copy ssh keys to container")
                log.Fatal(err)
            }

            os.Chmod(auth_keys_path, 0400)

            wget_installer_cmd := exec.Command("wget", "--no-check-certificate", "https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl", "-O" + vzroot_path + "/root/fastnetmon_install.pl") 
            wget_installer_cmd.Run()

            if err != nil {
                log.Println("Can't download FastNetMon installer to container")
                log.Fatal(err)
            }

            // Remove ssh known hosst file because in other case ssh will fail
            os.Remove("/root/.ssh/known_hosts")

            // perl /root/fastnetmon_install.pl --use-git-master --create-binary-bundle --build-binary-environment"
            // install_cmd := exec.Command("ssh", "-lroot", ip_address, "perl", "/root/fastnetmon_install.pl")
            install_cmd := exec.Command("ssh", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "-lroot", ip_address, "perl", "/root/fastnetmon_install.pl", "--use-git-master", "--create-binary-bundle", "--build-binary-environment")

            var stdout_output bytes.Buffer
            var stderr_output bytes.Buffer

            install_cmd.Stdout = &stdout_output
            install_cmd.Stderr = &stderr_output

            install_cmd.Run()

            fmt.Println("Command call on " + distribution_name + " finished")

            fmt.Println("stdout")
            fmt.Println(stdout_output.String())

            fmt.Println("stderr")
            fmt.Println(stderr_output.String())

            fmt.Println("Get produced data from container to host system")

            copy_cmd := exec.Command("cp", "-rf", "/vz/root/" + ctid_as_string + "/tmp/result_data", target_directory + "/" + distribution_name) 
            copy_cmd.Run()

            // Stop it 
            fmt.Println("Stop container ", ctid_as_string)
            stop_cmd := exec.Command("/usr/sbin/vzctl", "stop", ctid_as_string);
            err = stop_cmd.Run()
 
            if err != nil {
                log.Println("stop failed")
                log.Fatal(err)
            }

            fmt.Println("Destroy container ", ctid_as_string)
            destroy_cmd := exec.Command("/usr/sbin/vzctl", "destroy", ctid_as_string);
            err = destroy_cmd.Run()

            if err != nil {
                log.Println("destroy failed")
                log.Fatal(err)
            }
        } (element_number, distro)
    }

    wg.Wait()
}
