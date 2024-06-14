import datetime
import ipaddress
import os
import socket

QUIT = False
IPV4_NET = []
OUT_FILE_HOSTS = ''
OUT_FILE_PORTS = ''
OUT_FILE_HOSTS_PORTS = ''

class application:
    NAME = 'hostRecon'
    VERSION = '1.0'

class colours:
    BGBLACK = '\033[40m'
    BGRED = '\033[41m'
    BGGREEN = '\033[42m'
    BGBROWN = '\033[43m'
    BGBLUE = '\033[44m'
    BGPURPLE = '\033[45m'
    BGCYAN = '\033[46m'
    BGLIGHTGRAY = '\033[47m'
    GRAY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    LIGHTGRAY = '\033[97m'
    NONE = '\033[0m'
    BOLD = '\033[1m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKE = '\033[9m'
    UNDERLINE2 = '\033[21m'

def validate_directory(directory):
    try:
        return (os.path.isdir(directory))
    except Exception as ex:
        return False

def validate_ipv4_address(address):
    try:
        ipAddress = ipaddress.ip_address(address)
        if not isinstance(ipAddress, ipaddress.IPv4Address): raise Exception
        return True
    except Exception as ex:
        return False

def validate_ipv4_address_range(begIpAddress, endIpAddress):
    try:
        return (ipaddress.ip_address(begIpAddress) <= ipaddress.ip_address(endIpAddress))
    except Exception as ex:
        return False

def validate_ipv4_network(cidr):
    try:
        ipv4Network = ipaddress.IPv4Network(cidr)
        return True
    except Exception as ex:
        return False

def validate_port_number(port):
    try:
        return (port.isdigit() and int(port) in range(0,65536))
    except Exception as ex:
        return False

def generate_ipv4_network_CIDR(ipv4Net):
    try:
        ipv4Network = ipaddress.IPv4Network(ipv4Net)
        return ipv4Network
    except Exception as ex:
        print_output('error', ex)

def generate_ipv4_network_IP(begIpAddress, endIpAddress):
    try:
        firstIpAddress = ipaddress.ip_address(begIpAddress)
        lastIpAddress = ipaddress.ip_address(endIpAddress)
        ipv4Network = [ipaddr for ipaddr in ipaddress.summarize_address_range(firstIpAddress, lastIpAddress)]
        return ipv4Network
    except Exception as ex:
        print_output('error', ex)

def get_hostName_by_ip(ipAddress):
    try:
        hostName = socket.gethostbyaddr(ipAddress)[0]
    except Exception as ex:
        hostName = 'Unknown'
    finally:
        return hostName

def get_port_status(ipAddress, port):
    try:
        with socket.create_connection((ipAddress, port), 5) as sock:
            blnOpen = True
    except Exception as ex:
        blnOpen = False
    finally:
        return blnOpen

def determine_host_names_open_ports(ipv4Net, ports, outputType, outputFile = '', blnSkipUnknown = True):
    try:
        blnOutFile = (outputFile != '')
        blnOutScreen = (outputType != 'f')
        if blnOutFile: fileOut = open(outputFile, 'a')
        if blnOutScreen: generate_screen_results(ports=ports, blnShowHostName=True, blnHeader=True)
        i, fnd = 0, 0
        for net in ipv4Net:
            for ipa in ipaddress.IPv4Network(net):
                portsStatus = []
                ipAddress = str(ipa)
                if not blnOutScreen: print_output('progress', '\nChecking: ' + ipAddress)
                hostName = get_hostName_by_ip(ipAddress)
                if (hostName.lower() != 'unknown') or ((hostName.lower() == 'unknown') and not blnSkipUnknown):
                    openPorts = ''
                    for port in ports:
                        if not blnOutScreen: print_output('progress', '\nChecking: ' + ipAddress + ':' + str(port))
                        portOpen = get_port_status(ipAddress, port)
                        openPorts += (str(port) + ',' if portOpen else ',')
                        portsStatus.append(str(port) + '=open' if portOpen else str(port) + '=closed')
                    openPorts = openPorts.removesuffix(',')
                    if blnOutFile: fileOut.write(ipAddress + ',' + hostName + ',' + openPorts + '\n')
                    if blnOutScreen: generate_screen_results(ipAddress, hostName, portsStatus, blnShowHostName=True, blnHeader=False)
                    if (hostName.lower() != 'unknown'): fnd += 1
                i += 1
        addressesMsg = (str(i) + ' address scanned' if (i == 1) else str(i) + ' addresses scanned')
        hostsMsg = (str(fnd) + ' host name found' if (i == 1) else str(i) + ' host names found')
        print_output('info', '\nScan complete: ' + addressesMsg + ' | ' + hostsMsg)
        if blnOutFile: print_output('info', '  Output file: ' + outputFile)
    except Exception as ex:
        print_output('error', ex)
    finally:
        if ('fileOut' in locals() and blnOutFile): fileOut.close()

def determine_host_names(ipv4Net, outputType, outputFile = '', blnSkipUnknown = True):
    try:
        blnOutFile = (outputFile != '')
        blnOutScreen = (outputType != 'f')
        if blnOutFile: fileOut = open(outputFile, 'a')
        if blnOutScreen: generate_screen_results(blnShowHostName=True, blnHeader=True)
        i, fnd = 0, 0
        for net in ipv4Net:
            for ipa in ipaddress.IPv4Network(net):
                ipAddress = str(ipa)
                if not blnOutScreen: print_output('progress', '\nChecking: ' + ipAddress)
                hostName = get_hostName_by_ip(ipAddress)
                if (hostName.lower() != 'unknown') or ((hostName.lower() == 'unknown') and not blnSkipUnknown):
                    if blnOutFile: fileOut.write(ipAddress + ',' + hostName + '\n')
                    if blnOutScreen: generate_screen_results(ipAddress, hostName, blnShowHostName=True, blnHeader=False)
                    if (hostName.lower() != 'unknown'): fnd += 1
                i += 1
        addressesMsg = (str(i) + ' address scanned' if (i == 1) else str(i) + ' addresses scanned')
        hostsMsg = (str(fnd) + ' host name found' if (i == 1) else str(i) + ' host names found')
        print_output('info', '\nScan complete: ' + addressesMsg + ' | ' + hostsMsg)
        if blnOutFile: print_output('info', '  Output file: ' + outputFile)
    except Exception as ex:
        print_output('error', ex)
    finally:
        if ('fileOut' in locals() and blnOutFile): fileOut.close()

def determine_open_ports(ports, outputType, outputFile = '', ipv4Net = []):
    try:
        blnOutFile = (outputFile != '')
        blnOutScreen = (outputType != 'f')
        if blnOutFile: fileOut = open(outputFile, 'a')
        if blnOutScreen: generate_screen_results(ports=ports, blnShowHostName=False, blnHeader=True)
        i = 0
        for net in ipv4Net:
            for ipa in ipaddress.IPv4Network(net):
                ipAddress = str(ipa)
                hostName = ''
                openPorts = ''
                portsStatus = []
                for port in ports:
                    if not blnOutScreen: print_output('progress', '\nChecking: ' + ipAddress + ':' + str(port))
                    portOpen = get_port_status(ipAddress, port)
                    openPorts += (str(port) + ',' if portOpen else ',')
                    portsStatus.append(str(port) + '=open' if portOpen else str(port) + '=closed')
                openPorts = openPorts.removesuffix(',')
                if blnOutFile: fileOut.write(ipAddress + ',' + openPorts + '\n')
                if blnOutScreen: generate_screen_results(ipAddress, hostName, portsStatus, blnShowHostName=False, blnHeader=False)
                i += 1
        addressesMsg = (str(i) + ' address scanned' if (i == 1) else str(i) + ' addresses scanned')
        print_output('info', '\nScan complete: ' + addressesMsg)
        if blnOutFile: print_output('info', '  Output file: ' + outputFile)
    except Exception as ex:
        print_output('error', ex)
    finally:
        if ('fileOut' in locals() and blnOutFile): fileOut.close()

def generate_screen_results(ipAddress = '', hostName = '', ports = [], blnShowHostName=False, blnHeader=False):
    try:
        if blnHeader:
            header = '\n' + 'IP Address'.ljust(16)
            divider = '-'*16
            if blnShowHostName:
                header += '|' + 'Host Name'.ljust(50)
                divider += '|' + '-'*50
            for p in ports:
                header += '|' + str(p).rjust(7)
                divider += '|' + '-'*7
            print_output('plain', header)
            print_output('plain', divider)
        else:
            if len(hostName) > 50: hostName = hostName[0:47] + '...'
            entry = ipAddress.ljust(16)
            if blnShowHostName: entry += '|' + hostName.ljust(50)
            for p in ports:
                entry += '|' + p.split('=')[1].rjust(7)
            print_output('plain', entry)
    except Exception as ex:
        print_output('error', ex)

def print_output(type, output=''):
    try:
        if (type.lower() == 'banner'):
            prefix = '\n' + ':'*40 + '[ '
            suffix = ' ]' + ':'*40
            output = prefix + application.NAME + ' ' + application.VERSION + suffix
            print(colours.CYAN + output + colours.NONE)
            caption = 'The hostRecon utility can be used to obtain host names and to determine whether certain ports are \nopen or closed given a set of IP addresses and port numbers.  Results can be written to csv file.'
            print(colours.CYAN + caption + colours.NONE)
        if (type.lower() == 'menu'):
            menuHeading = '\n[ Menu ]'
            print(colours.CYAN + menuHeading + colours.NONE)
            menuOptions = '1. Obtain host names by IP address/range\n2. Check for specified open ports\n3. Obtain host names and open ports\n4. Quit'
            print(colours.CYAN + menuOptions + colours.NONE)
        if (type.lower() == 'error'):
            print(colours.RED + output + colours.NONE)
        if (type.lower() == 'info'):
            print(colours.YELLOW + output + colours.NONE)
        if (type.lower() == 'plain'):
            print(colours.NONE + output + colours.NONE)
        if (type.lower() == 'progress'):
            print(colours.MAGENTA + output + colours.NONE, end='\r', flush=True)
        if (type.lower() == 'valid'):
            print(colours.GREEN + output + colours.NONE)
    except Exception as ex:
        print(colours.RED + ex + colours.NONE)

def menu_get_ipv4Net():
    try:
        ipMethod = ''
        ipv4Net = []
        while ipMethod not in ['s', 'r', 'c']:
            ipMethod = input('\nProvide IPv4 addresses by single IP, IP range, or CIDR notation? [s/r/c]: ').strip().lower()
        if ipMethod == 's':
            blnValid = False
            while not blnValid:
                ipSingle = input('\nEnter an IPv4 address (ex: 192.168.1.101): ').strip()
                blnValid = validate_ipv4_address(ipSingle)
                if not blnValid: print_output('error', 'Invalid IPv4 address')
                ipv4Net = generate_ipv4_network_IP(ipSingle, ipSingle)
            print_output('valid', ipSingle)
        elif ipMethod == 'r':
            blnValid = False
            while not blnValid:
                ipBegin = input('\nEnter the first IPv4 address in the range (ex: 192.168.1.101): ').strip()
                blnValid = validate_ipv4_address(ipBegin)
                if not blnValid: print_output('error', 'Invalid IPv4 address')
            print_output('valid', ipBegin)
            blnValid = False
            while not blnValid:
                ipEnd = input('\nEnter the last IPv4 address in the range (ex: 192.168.1.150): ').strip()
                blnValid = validate_ipv4_address(ipEnd)
                if not blnValid: print_output('error', 'Invalid IPv4 address')
                blnValid = validate_ipv4_address_range(ipBegin, ipEnd)
                if not blnValid: print_output('error', 'Last IP address must be greater than first IP address.')
                ipv4Net = generate_ipv4_network_IP(ipBegin, ipEnd)
            print_output('valid', ipEnd)
        elif (ipMethod == 'c'):
            blnValid = False
            while not blnValid:
                cidr = input('\nEnter an IPv4 network using CIDR notation (ex: 192.168.1.0/24): ').strip()
                blnValid = validate_ipv4_network(cidr)
                if not blnValid: print_output('error', 'Invalid IPv4 network')
            print_output('valid', cidr)
            ipv4Net.append(cidr)
        global IPV4_NET
        IPV4_NET = ipv4Net
        return ipv4Net
    except Exception as ex:
        print_output('error', ex)

def menu_get_output_type():
    try:
        outType = ''
        while outType not in ['s', 'f', 'b']:
            outType = input('\nOutput results to screen, file, or both? [s/f/b]: ').strip().lower()
        return outType
    except Exception as ex:
        print_output('error', ex)

def menu_get_output_dir():
    try:
        dirName, dirType = '', ''
        pwd = os.getcwd()
        while dirType not in ['p', 'c']:
            dirType = input('\nProvide output file location using present directory (' + pwd + ') or custom directory? [p/c]: ').strip().lower()
        if (dirType == 'p'):
            dirName = pwd
        elif (dirType == 'c'):
            blnValid = False
            while not blnValid:
                dirName = input('\nProvide custom directory location for output file (ex: /home/user/): ').strip()
                blnValid = validate_directory(dirName)
                if not blnValid: print_output('error', 'Invalid directory path')
        print_output('valid', dirName)
        return dirName
    except Exception as ex:
        print_output('error', ex)

def menu_skip_unknown():
    try:
        blnSkipUnknown = False
        omitUnknown = ''
        while omitUnknown not in ['y', 'n']:
            omitUnknown = input('\nOmit unknown/unfound host entries from output? [y/n]: ').strip().lower()
        blnSkipUnknown = (omitUnknown == 'y')
        return blnSkipUnknown
    except Exception as ex:
        print_output('error', ex)

def menu_use_existing_ipv4net_as_input():
    try:
        blnUseExistingNet = False
        useExistingNet = ''
        while useExistingNet not in ['y', 'n']:
            ipv4Net = ', '.join(map(str, IPV4_NET))
            useExistingNet = input('\nUse existing IPvNet (' + ipv4Net + ') as input for port scan? [y/n]: ').strip().lower()
        blnUseExistingNet = (useExistingNet == 'y')
        return blnUseExistingNet
    except Exception as ex:
        print_output('error', ex)

def menu_get_port_numbers():
    try:
        blnError = True
        while blnError:
            ports = []
            portNumbers = input('\nProvide port numbers to scan as integers between 0 and 65535, separated by commas (ex: 22, 80, 443, 5432): ').strip()
            raw = portNumbers.split(',')
            for r in raw:
                r = r.strip()
                if not validate_port_number(r):
                    print_output('error', 'The value ' + r + ' is not an valid port number.')
                    blnError = True
                    break
                else:
                    ports.append(int(r))
                    blnError = False
        prt = ', '.join(map(str, ports))
        print_output('valid', prt)
        return ports
    except Exception as ex:
        print_output('error', ex)

def menu_option_1():
    try:
        ipv4Net = ''
        if (len(IPV4_NET) > 0):
            blnUseExistingIPv4Net = menu_use_existing_ipv4net_as_input()
            ipv4Net = (IPV4_NET if blnUseExistingIPv4Net else menu_get_ipv4Net())
        else:
            ipv4Net = menu_get_ipv4Net()
        outputType = menu_get_output_type()
        if (outputType != 's'):
            outputDir = menu_get_output_dir()
            outputFile = os.path.join(outputDir, 'hostRecon-names-' + datetime.datetime.today().strftime('%Y%m%d%H%M%S') + '.csv')
        else:
            outputFile = ''
        global OUT_FILE_HOSTS
        OUT_FILE_HOSTS = outputFile
        blnSkipUnknown = menu_skip_unknown()
        determine_host_names(ipv4Net, outputType, outputFile, blnSkipUnknown)
    except Exception as ex:
        print_output('error', ex)

def menu_option_2():
    try:
        ipv4Net = ''
        if (len(IPV4_NET) > 0):
            blnUseExistingIPv4Net = menu_use_existing_ipv4net_as_input()
            ipv4Net = (IPV4_NET if blnUseExistingIPv4Net else menu_get_ipv4Net())
        else:
            ipv4Net = menu_get_ipv4Net()
        outputType = menu_get_output_type()
        if (outputType != 's'):
            outputDir = menu_get_output_dir()
            outputFile = os.path.join(outputDir, 'hostRecon-ports-' + datetime.datetime.today().strftime('%Y%m%d%H%M%S') + '.csv')
        else:
            outputFile = ''
        global OUT_FILE_PORTS
        OUT_FILE_PORTS = outputFile
        ports = menu_get_port_numbers()
        determine_open_ports(ports, outputType, outputFile, ipv4Net)
    except Exception as ex:
        print_output('error', ex)

def menu_option_3():
    try:
        ipv4Net = ''
        if (len(IPV4_NET) > 0):
            blnUseExistingIPv4Net = menu_use_existing_ipv4net_as_input()
            ipv4Net = (IPV4_NET if blnUseExistingIPv4Net else menu_get_ipv4Net())
        else:
            ipv4Net = menu_get_ipv4Net()
        outputType = menu_get_output_type()
        if (outputType != 's'):
            outputDir = menu_get_output_dir()
            outputFile = os.path.join(outputDir, 'hostRecon-namesports-' + datetime.datetime.today().strftime('%Y%m%d%H%M%S') + '.csv')
        else:
            outputFile = ''
        global OUT_FILE_HOSTS_PORTS
        OUT_FILE_HOSTS_PORTS = outputFile
        blnSkipUnknown = menu_skip_unknown()
        ports = menu_get_port_numbers()
        determine_host_names_open_ports(ipv4Net, ports, outputType, outputFile, blnSkipUnknown)
    except Exception as ex:
        print_output('error', ex)

def menu_option_4():
    try:
        global QUIT
        QUIT = True
    except Exception as ex:
        print_output('error', ex)

def main_menu():
    try:
        print_output('banner')
        print_output('menu')
        menuOption = ''
        while menuOption not in ['1', '2', '3', '4', 'q', 'Q']:
             menuOption = input('\nEnter a selection from the menu: ').strip().lower()
        if (menuOption == '1'):
            menu_option_1()
        elif (menuOption == '2'):
            menu_option_2()
        elif (menuOption == '3'):
            menu_option_3()
        elif (menuOption in ('4', 'q', 'Q')):
            menu_option_4()
    except Exception as ex:
        print_output('error', ex)

if __name__ == '__main__':
    while not QUIT:
        main_menu()
