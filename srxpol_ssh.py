from ipaddress import *
import random
import string
import datetime
import re, os, sys, socket
import getopt
from netmiko import Netmiko
import time
import pyperclip


# generate ready to use policy with mixed zones and scheduler
# do not create policy in DC phy if src zone IBS and dst untrust
# do not create policy in DC4 if src zone VPN and dst untrust


def func_random_str(str_length=8):  # Generate a random string of letters and digits
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(str_length))


rnd_string = func_random_str()
policy_name = 'TMP_' + rnd_string
policy_type = 'temporary'
delta_days = None


def main(argv):
    global policy_name
    global policy_type
    global delta_days
    try:
        opts, args = getopt.getopt(argv, "hp:d:")
    except getopt.GetoptError:
        print('unknown options!\nusage:\n' + sys.argv[0] + ' [-p <policy_name> -d <days>]')
        sys.exit(1)
    for opt, arg in opts:
        if opt == '-h':
            print('usage:\n' + sys.argv[0] + ' [-p <policy_name> -d <days>]')
            sys.exit()
        elif opt in '-p':
            policy_name = arg
            policy_type = 'persistent'
        elif opt in '-d':
            delta_days = arg


main(sys.argv[1:])  # handle script arguments

# define file names
file_rule = 'rule.txt'
file_output = 'OUT-policy.jun'

# =========================================
list_src_hosts = []
list_dst_hosts = []
list_app = []
# rule file parsing
try:
    with open(file_rule) as hosts_list:
        for line in hosts_list:
            line = line.strip()  # remove \n
            line = re.sub(r'\s+', '', line)  # remove whitespaces
            linesplit = line.split(',')
            if linesplit[0] == 'src':
                linesplit.pop(0)  # remove first element
                for h in linesplit:  # create list of src IPs
                    list_src_hosts.append(h)
            if linesplit[0] == 'dst':
                linesplit.pop(0)  # remove first element
                for h in linesplit:  # create list of dst IPs
                    list_dst_hosts.append(h)
            if linesplit[0] == 'app':
                linesplit.pop(0)  # remove first element
                for ap in linesplit:
                    list_app.append(ap)
except FileNotFoundError:
    print('file', file_rule, 'not found')
    time.sleep(5)
    sys.exit(1)

hosts_list.close()

try:
    os.remove(file_output)
except FileNotFoundError:
    pass

out_file = open(file_output, "a")


# make output file empty
def del_out_file():
    open(file_output, 'w').close()


# create applications
for dst_app in list_app:
    if re.match(r'\d{1,5}$', dst_app):  # match 12345
        out_file.write('set applications application TCP-' + dst_app + ' protocol tcp destination-port ' + dst_app + '\n')
    elif re.match(r'(tcp|udp)+-\d{1,5}-\d{1,5}$', dst_app, flags=re.IGNORECASE):  # match tcp-12345-12400
        dproto = (dst_app.split('-')[0]).lower()
        dport_s = dst_app.split('-')[1]
        dport_e = dst_app.split('-')[2]
        out_file.write('set applications application ' + dst_app.upper() + ' protocol ' + dproto + ' destination-port ' + dport_s + '-' + dport_e + '\n')
    elif re.match(r'(tcp|udp)-\d{1,5}$', dst_app, flags=re.IGNORECASE):  # match tcp-12345
        dproto = (dst_app.split('-')[0]).lower()
        dport_s = dst_app.split('-')[1]
        out_file.write('set applications application ' + dst_app.upper() + ' protocol ' + dproto + ' destination-port ' + dport_s + '\n')
    elif re.search(r'icmp', dst_app, flags=re.IGNORECASE):
        continue
    elif re.match(r'junos-', dst_app):
        continue
    elif re.match(r'any', dst_app, flags=re.IGNORECASE):
        continue
    else:
        print('unknown application', dst_app)
        del_out_file()
        sys.exit(1)

out_file.write('\n')

file_creds = 'creds.txt'
credentials = {}
try:
    with open(file_creds, 'r') as cr:
        for line in cr:
            user, pwd = line.strip().split(':')
            credentials[user] = user
            credentials[pwd] = pwd
except FileNotFoundError:
    print('File', file_creds, 'not found')
    time.sleep(5)
    del_out_file()
    sys.exit(1)

print('Choose device to connect:\n'
      '  1. dc2-srx550 (10.2.100.5)\n'
      '  2. dc4-vSRX (172.20.251.8)\n'
      '  3. Enter your address\n')
input1 = input('Enter number [1]: ')
if input1 == '1':
    device_ip = '10.2.100.5'
elif input1 == '2':
    device_ip = '172.20.251.8'
elif input1 == '':
    device_ip = '10.2.100.5'
elif input1 == '3':
    device_ip = input('Enter IP address or DNS name: ')
else:
    print('incorrect choise!', input1)
    time.sleep(5)
    sys.exit(1)

junos1 = {
    "host": device_ip,
#    "host": 'dc2-srx550',
    "username": credentials[user],
    "password": credentials[pwd],
    "device_type": "juniper",
}


# connecting to device
try:
    print('connecting to', junos1['host'])
    net_connect = Netmiko(**junos1)
    dev_prompt = net_connect.find_prompt()
except Exception as conn:
    ex_templ = "An exception of type {0} occurred. Arguments:\n{1!r}"
    ex_msg = ex_templ.format(type(conn).__name__, conn.args)
    print(ex_msg)
    del_out_file()
    time.sleep(5)
    sys.exit(1)


def get_zone(addr_z):
    if re.search(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', addr_z):  # match domain name
        try:
            dns_ip2 = socket.gethostbyname(addr_z)  # resolve IP domain name
        except socket.gaierror:
            print('cannot resolve', addr_z)
            del_out_file()
            net_connect.disconnect()
            sys.exit(1)
        get_dns = get_zone(dns_ip2)
        return addr_z, get_dns[1]
    #
    try:
        IPv4Address(addr_z)  # validate IP address
        command1 = "show route table inet.0 " + addr_z
        output1 = net_connect.send_command(command1)
        via_if = re.search(r'(?<=via\s).+', output1)  # match output interface name
        rt_net = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', output1)  # match net address in output (0.0.0.0/0)
        net = rt_net.group(0)
        command2 = "show interfaces " + str(via_if.group(0)) + ' | match Security:'
        output2 = net_connect.send_command(command2)
        zone_name = output2.split(':')[2].strip()
    except (AddressValueError, ValueError):
        print('incorrect address:', addr_z)
        del_out_file()
        net_connect.disconnect()
        sys.exit(1)
    #
    try:
        if re.search(r'.+/32$', net):  # if address is junos local it return /32 address, network address not shown
            return addr_z, zone_name
        if str(IPv4Network(net).network_address) == str(addr_z):  # check if IP is a network address
            return net, zone_name
        if IPv4Address(addr_z) in IPv4Network(net):
            return addr_z, zone_name
    except (AddressValueError, ValueError):
        pass


# create dictionary for sources
d_srcZoneIP = dict()
for h_s in list_src_hosts:
    if re.search(r'^[^.]+$', h_s):  # match string not containing dot character
        h_s = h_s + '.brc.local'  # suggest brc.local domain
    src1 = get_zone(h_s)
    if src1 is None:
        print('unable to define zone for:', h_s)
        print('check address is correct')
        del_out_file()
        net_connect.disconnect()
        sys.exit(1)
    if src1[1] in d_srcZoneIP.keys():  # if dict contain key (zone name) then append ip address to list of values
        l1 = d_srcZoneIP.get(src1[1])  # get values by key and add assign to string
        l1 = l1 + ',' + src1[0]  # append value to string
        d_srcZoneIP[src1[1]] = l1  # update dict
    else:
        d_srcZoneIP[src1[1]] = src1[0]  # create new key:value

# create dictionary for destinations
d_dstZoneIP = dict()
for h_d in list_dst_hosts:
    if re.search(r'^[^.]+$', h_d):
        h_d = h_d + '.brc.local'
    dst1 = get_zone(h_d)
    if dst1 is None:
        print('unable to define zone for:', h_d)
        print('check address is correct')
        del_out_file()
        net_connect.disconnect()
        sys.exit(1)
    if dst1[1] in d_dstZoneIP.keys():
        l2 = d_dstZoneIP.get(dst1[1])
        l2 = l2 + ',' + dst1[0]
        d_dstZoneIP[dst1[1]] = l2
    else:
        d_dstZoneIP[dst1[1]] = dst1[0]


scheduler_name = ''
if policy_type == 'temporary':
    # get current date
    now_date = datetime.datetime.now()
    now_month = '{:02d}'.format(now_date.month)  # 2 digit format
    now_day = '{:02d}'.format(now_date.day)
    now_hour = '{:02d}'.format(now_date.hour)
    #
    # add 1 week to current date
    # Other Parameters you can pass in to timedelta:
    # days, seconds, microseconds,
    # milliseconds, minutes, hours, weeks
    if delta_days is None:  # if no option -d specified
        delta_days = 7
    elif int(delta_days) < 1 or int(delta_days) > 365:
        print('option \'days\' must be in range 1-365')
        del_out_file()
        net_connect.disconnect()
        sys.exit(1)
    future_date = datetime.datetime.now() + datetime.timedelta(days=int(delta_days))
    fd_year = '{:02d}'.format(future_date.year)
    fd_month = '{:02d}'.format(future_date.month)
    fd_day = '{:02d}'.format(future_date.day)
    fd_hour = '{:02d}'.format(future_date.hour)
    start_date = str(now_date.year) + '-' + now_month + '-' + now_day + '.' + now_hour + ':00'
    stop_date = fd_year + '-' + fd_month + '-' + fd_day + '.23:59'
    #
    # create scheduler
    scheduler_name = policy_name  # scheduler name is tha same as policy name
    set_sheduler = 'set schedulers scheduler ' + scheduler_name + ' start-date ' + start_date + ' stop-date ' + stop_date
    out_file.write(set_sheduler)
    out_file.write('\n\n')


# create address book for sources
for srcKey, srcValue in d_srcZoneIP.items():
    srcZoneIPlist = d_srcZoneIP[srcKey].split(',')
    for srcZoneIP in srcZoneIPlist:
        if re.search(r'^[^.]+$', srcZoneIP):  # match string not containing dot character
            srcZoneIP = srcZoneIP + '.brc.local'  # suggest brc.local domain
        if re.search(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', srcZoneIP):  # match domain name
            out_file.write('set security zones security-zone ' + srcKey + ' address-book address ' + srcZoneIP + ' dns-name ' + srcZoneIP + '\n')
        if '0.0.0.0' in srcZoneIP:
            continue
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', srcZoneIP):  # match network address
            srcZoneIP = re.sub(r'/', '_', srcZoneIP)
            net_name = 'net_' + srcZoneIP
            net_addr = srcZoneIP.split('_')[0]
            net_prefix = srcZoneIP.split('_')[1]
            out_file.write('set security zones security-zone ' + srcKey + ' address-book address ' + net_name + ' ' + net_addr + '/' + net_prefix + '\n')
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', srcZoneIP):  # match IP address
            out_file.write('set security zones security-zone ' + srcKey + ' address-book address ' + srcZoneIP + ' ' + srcZoneIP + '/32\n')
# create address book for destinations
for dstKey, dstValue in d_dstZoneIP.items():
    dstZoneIPlist = d_dstZoneIP[dstKey].split(',')
    for dstZoneIP in dstZoneIPlist:
        if re.search(r'^[^.]+$', dstZoneIP):  # match string not containing dot character
            dstZoneIP = dstZoneIP + '.brc.local'  # suggest brc.local domain
        if re.search(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', dstZoneIP):  # match domain name
            out_file.write('set security zones security-zone ' + dstKey + ' address-book address ' + dstZoneIP + ' dns-name ' + dstZoneIP + '\n')
        if '0.0.0.0' in dstZoneIP:
            continue
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', dstZoneIP):  # match network address
            dstZoneIP = re.sub(r'/', '_', dstZoneIP)
            net_name = 'net_' + dstZoneIP
            net_addr = dstZoneIP.split('_')[0]
            net_prefix = dstZoneIP.split('_')[1]
            out_file.write('set security zones security-zone ' + dstKey + ' address-book address ' + net_name + ' ' + net_addr + '/' + net_prefix + '\n')
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dstZoneIP):  # match IP address
            out_file.write('set security zones security-zone ' + dstKey + ' address-book address ' + dstZoneIP + ' ' + dstZoneIP + '/32\n')

out_file.write('\n')

# create policies
policy_count = 0
except_zone_list = ['untrust', 'IBS', 'VPN']  # no traffic flow
for srcKey, srcValue in d_srcZoneIP.items():
    srcZoneIPlist = d_srcZoneIP[srcKey].split(',')
    for dstKey, dstValue in d_dstZoneIP.items():
        d_dstZoneIPlist = d_dstZoneIP[dstKey].split(',')
        if srcKey == dstKey:
            print('addresses belongs to the same zone - ' + srcKey + ':\n' +
                  'src: ' + srcValue + '\n' +
                  'dst: ' + dstValue + '\n')
            continue
        if srcKey in except_zone_list and dstKey in except_zone_list:
            print(f'skip policy creation for zone pair: {srcKey} - {dstKey}')
            continue
        for srcZoneIP in srcZoneIPlist:  # policy source addresses
            if '0.0.0.0' in srcZoneIP:
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match source-address any\n')
                continue
            if '/' in srcZoneIP:  # check if IP is network address
                srcZoneIP = 'net_' + re.sub(r'/', '_', srcZoneIP)
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match source-address ' + srcZoneIP + '\n')
            else:
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match source-address ' + srcZoneIP + '\n')
        for dstZoneIP in d_dstZoneIPlist:  # policy destination addresses
            if '0.0.0.0' in dstZoneIP:
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match destination-address any\n')
                continue
            if '/' in dstZoneIP:  # check if IP is network address
                dstZoneIP = 'net_' + re.sub(r'/', '_', dstZoneIP)
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match destination-address ' + dstZoneIP + '\n')
            else:
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match destination-address ' + dstZoneIP + '\n')
        for dst_app_rule in list_app:  # applications
            if re.match(r'\d{1,5}$', dst_app_rule):  # match 12345, suggest protocol TCP
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match application TCP-' + dst_app_rule.upper() + '\n')
            elif re.match(r'\w{1,3}\W\d{1,5}', dst_app_rule):  # match tcp-12345, udp-12345, tcp-10-20, udp-50-60
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match application ' + dst_app_rule.upper() + '\n')
            elif re.search(r'icmp', dst_app_rule, flags=re.IGNORECASE):
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match application junos-icmp-all\n')
            elif re.match(r'junos-', dst_app_rule):
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match application ' + dst_app_rule + '\n')
            elif re.match(r'any', dst_app_rule, flags=re.IGNORECASE):
                out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' match application any\n')
        out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' then permit\n')
        policy_count += 1
        if policy_type == 'temporary':
            out_file.write('set security policies from-zone ' + srcKey + ' to-zone ' + dstKey + ' policy ' + policy_name + ' scheduler-name ' + scheduler_name + '\n')
        out_file.write('\n')

# out_file.write('commit\n')

out_file.close()

if policy_count == 0:
    print('0 policies need to be created')
    net_connect.disconnect()
    del_out_file()
    sys.exit(1)

'''
# load commands to device
print('send config file', file_output, 'to device ...')
net_connect.send_config_from_file(config_file=file_output)
time.sleep(100)
'''

'''
try:
    print('commit changes ...')
    cmt = net_connect.commit()  # not working with SRX550/650 clusters
    print(cmt)
    time.sleep(120)
    print('commit copmleted!')
except Exception as rsn:
    msg_body = 'ERROR while commit on ' + junos1['host'] + '\n\n' + str(rsn)
    print(msg_body)
    print('rollback changes')
    net_connect.send_command('rollback')
    net_connect.disconnect()
    print('rollback completed!')
    sys.exit(1)
'''

net_connect.disconnect()

# copy file content to clipboard
fo = open(file_output, 'r').read()
pyperclip.copy(fo)

print(policy_count, 'policies created')

print('done!')
