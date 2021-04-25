from ipaddress import *
import random
import string
import datetime
import re, os, sys, socket
import getopt
from netmiko import Netmiko
import time


def func_random_str(str_length=8):  # Generate a random string of letters and digits
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(str_length))


def print_help():
    print(f'unknown options!\n'
          f'usage:\n'
          f'{sys.argv[0]} [-p <policy_name>] [-d <days>] [-c] [-s]\n'
          f'-c: commit changes\n'
          f'-s: skip policy creation if src and dst addresses belongs to the same zone\n')


# make output file empty
def del_out_file():
    open(file_output, 'w').close()


def get_zone(net_connect, addr_z):
    if re.search(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', addr_z):  # match domain name
        try:
            dns_ip2 = socket.gethostbyname(addr_z)  # resolve IP domain name
        except socket.gaierror:
            print(f'cannot resolve {addr_z}')
            del_out_file()
            net_connect.disconnect()
            sys.exit(1)
        get_dns = get_zone(net_connect, dns_ip2)
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
    except (AddressValueError, ValueError, AttributeError):
        print(f'incorrect address or no route to {addr_z}')
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


def main():
    rnd_string = func_random_str()
    policy_name = 'TMP_' + rnd_string
    policy_type = 'temporary'
    delta_days = None
    commit = 'no'  # no commit by default
    skip_same_zone = 'no'

    # define default domain name
    df_domain_name = '.domain.local'

    # define file names
    file_rule = 'rule.txt'
    file_output = 'OUT-policy.jun'

    # handle script arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:d:cs")
    except getopt.GetoptError:
        print_help()
        sys.exit(1)
    for opt, arg in opts:
        if opt == '-h':
            print_help()
            sys.exit()
        elif opt in '-p':  # create persistent policy with defined name
            policy_name = arg
            policy_type = 'persistent'
        elif opt in '-d':  # set policy expiration
            delta_days = arg
        elif opt == '-c':  # commit changes
            commit = 'yes'
        elif opt == '-s':  # skip same zone policy
            skip_same_zone = 'yes'


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
        print(f'file {file_rule} not found')
        time.sleep(5)
        sys.exit(1)

    try:
        os.remove(file_output)
    except FileNotFoundError:
        pass

    out_file = open(file_output, "a")

    # create applications
    for dst_app in list_app:
        if re.match(r'\d{1,5}$', dst_app):  # match 12345
            out_file.write(f'set applications application TCP-{dst_app} protocol tcp destination-port {dst_app}\n')
        elif re.match(r'(tcp|udp)+-\d{1,5}-\d{1,5}$', dst_app, flags = re.IGNORECASE):  # match tcp-12345-12400
            dproto = (dst_app.split('-')[0]).lower()
            dport_s = dst_app.split('-')[1]
            dport_e = dst_app.split('-')[2]
            out_file.write(f'set applications application {dst_app.upper()} protocol {dproto} destination-port {dport_s}-{dport_e}\n')
        elif re.match(r'(tcp|udp)-\d{1,5}$', dst_app, flags = re.IGNORECASE):  # match tcp-12345
            dproto = (dst_app.split('-')[0]).lower()
            dport_s = dst_app.split('-')[1]
            out_file.write(f'set applications application {dst_app.upper()} protocol {dproto} destination-port {dport_s}\n')
        elif re.search(r'icmp', dst_app, flags = re.IGNORECASE):
            continue
        elif re.match(r'junos-', dst_app):
            continue
        elif re.match(r'any', dst_app, flags = re.IGNORECASE):
            continue
        else:
            print(f'unknown application: {dst_app}')
            del_out_file()
            sys.exit(1)

    out_file.write('\n')

    device_ip = input('Enter IP address or DNS name to connect to: ')

    junos1 = {
        "host": device_ip,
        "username": 'userName',
        "password": 'P@ssw0rd',
        "device_type": "juniper",
    }


    # connecting to device
    try:
        print(f'connecting to {junos1["host"]} ... ', end = '')
        net_connect = Netmiko(**junos1)
        dev_prompt = net_connect.find_prompt()
    except Exception as conn:
        ex_templ = "\nAn exception of type {0} occurred. Arguments:\n{1!r}"
        ex_msg = ex_templ.format(type(conn).__name__, conn.args)
        print(ex_msg)
        del_out_file()
        sys.exit(1)
    print('ok')

    # create dictionary for sources
    d_srcZoneIP = dict()
    for h_s in list_src_hosts:
        if re.search(r'^[^.]+$', h_s):  # match string not containing dot character
            h_s = h_s + df_domain_name  # suggest default domain
        src1 = get_zone(net_connect, h_s)
        if src1 is None:
            print(f'unable to define zone for: {h_s}')
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
            h_d = h_d + df_domain_name
        dst1 = get_zone(net_connect, h_d)
        if dst1 is None:
            print(f'unable to define zone for: {h_d}')
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
        # add 1 week to the current date
        # Other parameters you can pass in to timedelta:
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
        start_date = f'{str(now_date.year)}-{now_month}-{now_day}.{now_hour}:00'
        stop_date = f'{fd_year}-{fd_month}-{fd_day}.23:59'
        #
        # create scheduler
        scheduler_name = policy_name  # scheduler name is the same as policy name
        set_sheduler = f'set schedulers scheduler {scheduler_name} start-date {start_date} stop-date {stop_date}'
        out_file.write(set_sheduler)
        out_file.write('\n\n')


    # create address book for sources
    for srcKey, srcValue in d_srcZoneIP.items():
        srcZoneIPlist = d_srcZoneIP[srcKey].split(',')
        for srcZoneIP in srcZoneIPlist:
            if re.search(r'^[^.]+$', srcZoneIP):  # match string not containing dot character
                srcZoneIP = srcZoneIP + df_domain_name  # suggest default domain
            if re.search(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', srcZoneIP):  # match domain name
                out_file.write(f'set security zones security-zone {srcKey} address-book address {srcZoneIP} dns-name {srcZoneIP}\n')
            if '0.0.0.0' in srcZoneIP:
                continue
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', srcZoneIP):  # match network address
                srcZoneIP = re.sub(r'/', '_', srcZoneIP)
                net_name = f'net_{srcZoneIP}'
                net_addr = srcZoneIP.split('_')[0]
                net_prefix = srcZoneIP.split('_')[1]
                out_file.write(f'set security zones security-zone {srcKey} address-book address {net_name} {net_addr}/{net_prefix}\n')
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', srcZoneIP):  # match IP address
                out_file.write(f'set security zones security-zone {srcKey} address-book address {srcZoneIP} {srcZoneIP}/32\n')
    # create address book for destinations
    for dstKey, dstValue in d_dstZoneIP.items():
        dstZoneIPlist = d_dstZoneIP[dstKey].split(',')
        for dstZoneIP in dstZoneIPlist:
            if re.search(r'^[^.]+$', dstZoneIP):  # match string not containing dot character
                dstZoneIP = f'{dstZoneIP}{df_domain_name}'  # suggest default domain
            if re.search(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', dstZoneIP):  # match domain name
                out_file.write(f'set security zones security-zone {dstKey} address-book address {dstZoneIP} dns-name {dstZoneIP}\n')
            if '0.0.0.0' in dstZoneIP:
                continue
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', dstZoneIP):  # match network address
                dstZoneIP = re.sub(r'/', '_', dstZoneIP)
                net_name = f'net_{dstZoneIP}'
                net_addr = dstZoneIP.split('_')[0]
                net_prefix = dstZoneIP.split('_')[1]
                out_file.write(f'set security zones security-zone {dstKey} address-book address {net_name} {net_addr}/{net_prefix}\n')
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dstZoneIP):  # match IP address
                out_file.write(f'set security zones security-zone {dstKey} address-book address {dstZoneIP} {dstZoneIP}/32\n')

    out_file.write('\n')

    # create policies
    policy_count = 0
    except_zone_list = ['']  # skip policy creation for these zone pairs
    for srcKey, srcValue in d_srcZoneIP.items():
        srcZoneIPlist = d_srcZoneIP[srcKey].split(',')
        for dstKey, dstValue in d_dstZoneIP.items():
            d_dstZoneIPlist = d_dstZoneIP[dstKey].split(',')

            if skip_same_zone == 'yes':
                if srcKey == dstKey:
                    print(f'addresses belongs to the same zone - {srcKey}:\n'
                        f'src: {srcValue}\n'
                        f'dst: {dstValue}\n')
                    continue

            if srcKey in except_zone_list and dstKey in except_zone_list:
                print(f'skip policy creation for zone pair: {srcKey} - {dstKey}')
                continue
            for srcZoneIP in srcZoneIPlist:  # policy source addresses
                if '0.0.0.0' in srcZoneIP:
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match source-address any\n')
                    continue
                if '/' in srcZoneIP:  # check if IP is network address
                    srcZoneIP = 'net_' + re.sub(r'/', '_', srcZoneIP)
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match source-address {srcZoneIP}\n')
                else:
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match source-address {srcZoneIP}\n')
            for dstZoneIP in d_dstZoneIPlist:  # policy destination addresses
                if '0.0.0.0' in dstZoneIP:
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match destination-address any\n')
                    continue
                if '/' in dstZoneIP:  # check if IP is network address
                    dstZoneIP = 'net_' + re.sub(r'/', '_', dstZoneIP)
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match destination-address {dstZoneIP}\n')
                else:
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match destination-address {dstZoneIP}\n')
            for dst_app_rule in list_app:  # applications
                if re.match(r'\d{1,5}$', dst_app_rule):  # match 12345, suggest protocol TCP
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match application TCP-{dst_app_rule.upper()}\n')
                elif re.match(r'\w{1,3}\W\d{1,5}', dst_app_rule):  # match tcp-12345, udp-12345, tcp-10-20, udp-50-60
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match application {dst_app_rule.upper()}\n')
                elif re.search(r'icmp', dst_app_rule, flags=re.IGNORECASE):
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match application junos-icmp-all\n')
                elif re.match(r'junos-', dst_app_rule):
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match application {dst_app_rule}\n')
                elif re.match(r'any', dst_app_rule, flags=re.IGNORECASE):
                    out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} match application any\n')
            out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} then permit\n')
            policy_count += 1
            if policy_type == 'temporary':
                out_file.write(f'set security policies from-zone {srcKey} to-zone {dstKey} policy {policy_name} scheduler-name {scheduler_name}\n')
            out_file.write('\n')

    out_file.close()

    if policy_count == 0:
        print('0 policies need to be created')
        net_connect.disconnect()
        del_out_file()
        sys.exit()


    # load commands to device
    if commit == 'yes':
        try:
            print(f'send config file {file_output} to device ...')
            cfg_snd_output = net_connect.send_config_from_file(config_file = file_output, exit_config_mode = False)
            print('commit changes ...')
            commit_changes = net_connect.commit()
            print(cfg_snd_output)
            print(commit_changes)
            if 'configuration check-out failed' in cfg_snd_output:
                print('Cannot commit changes! Rollback changes')
                rlb_output = net_connect.send_config_set('rollback')
                print(cfg_snd_output)
                print(rlb_output)
                net_connect.disconnect()
                sys.exit(1)
        except Exception as rsn:
            msg_body = f'ERROR while commit on {junos1["host"]}\n\n{str(rsn)}'
            print(msg_body)
            print('rollback changes')
            net_connect.send_command('rollback')
            net_connect.disconnect()
            print('rollback completed!')
            sys.exit(1)

    net_connect.disconnect()

    print(f'{policy_count} policies created')

    print('done!')


if __name__ == '__main__':
    main()
