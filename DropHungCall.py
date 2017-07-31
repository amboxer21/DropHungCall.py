#!/usr/bin/env python
# coding: interpy

import sys,spur,re

global regex
#servers = ["vhpbx0","vhpbx1","vhpbx2","vhpbx3","mg0","mg1","mg2","mg3","mg4","mg5","mg6"]
servers = ["mg0","mg1","mg2","mg3","mg4","mg5","mg6"]

def tunnel(server, uname, passwd, ast_command):
    global regex
    shell = spur.SshShell(hostname=server, username=uname, password=passwd)
    regex = shell.run(["sh", "-c", "/usr/sbin/asterisk -rx \"#{ast_command}\""]).output

def hangup_channel(server):
    ans     = raw_input("Enter a SIP channel to hangup: ")
    channel = re.search("(SIP)\/\w+-\w+", ans)
    if channel is not None and channel.group(1) == "SIP":
        ans = raw_input("Hangup channel -> [#{channel.group()}](\"YES\")? ")
        if re.search("YES", ans):
            print "Hanging up SIP channel on #{server}"
            tunnel(server, 'your username goes here', 'your password goes here', "soft hangup #{channel.group()}")
        else:
            print "SIP channel [channel.group()] was not hung up. GOOD BYE!"
    else:
        print "#{ans} is not a known SIP channel. GOOD BYE!"

def asterisk_rx(number):
    count = 0
    global regex
    for server in servers:
        tunnel(server, 'your username goes here', 'your password goes here', 'core show channels verbose')
        result = str(re.findall("SIP.*" + number + ".*", str(regex)))[1:-1].replace("\'","")

        if result:
            print result
            hangup_channel(server)
            break
        else:
            count = count + 1

        if count == 7:
            print "Number not found!"

asterisk_rx(sys.argv[1])
