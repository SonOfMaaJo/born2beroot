#!/bin/bash

# Architecture
arch=$(uname -a)

# Physical CPUs
cpuf=$(grep "physical id" /proc/cpuinfo | wc -l)

# Virtual CPUs
cpuv=$(grep "processor" /proc/cpuinfo | wc -l)

# RAM
ram_total=$(free -m | grep Mem | awk '{print $2}')
ram_used=$(free -m | grep Mem | awk '{print $3}')
ram_percent=$(free -m | grep Mem | awk '{printf("%.2f"), $3/$2*100}')

# Disk
disk_total=$(df -m --total | grep total | awk '{print $2}')
disk_used=$(df -m --total | grep total | awk '{print $3}')
disk_percent=$(df -m --total | grep total | awk '{print $5}')

# CPU Load
cpu_load=$(top -bn1 | grep "^%Cpu" | cut -c 9- | xargs | awk '{printf("%.1f%%"), $1 + $3}')

# Last boot
lb=$(who -b | awk '$1 == "system" {print $3 " " $4}')

# LVM use
lvm_use=$(if [ $(lsblk | grep "lvm" | wc -l) -gt 0 ]; then echo yes; else echo no; fi)

# TCP Connections
tcpc=$(ss -ta | grep ESTAB | wc -l)

# User log
ulog=$(users | wc -w)

# Network
ip=$(hostname -I)
mac=$(ip link | grep "link/ether" | awk '{print $2}')

# Sudo
cmnd=$(journalctl _COMM=sudo | grep COMMAND | wc -l)

wall "	#Architecture: $arch
	#CPU physical : $cpuf
	#vCPU : $cpuv
	#Memory Usage: $ram_used/${ram_total}MB ($ram_percent%)
	#Disk Usage: $disk_used/${disk_total}Mb ($disk_percent)
	#CPU load: $cpu_load
	#Last boot: $lb
	#LVM use: $lvm_use
	#Connections TCP : $tcpc ESTABLISHED
	#User log: $ulog
	#Network: IP $ip ($mac)
	#Sudo : $cmnd cmd"
