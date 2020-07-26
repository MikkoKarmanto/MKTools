from pysnmp import hlapi
from pysnmp.proto import rfc1902
from sys import argv
from pythonping import ping
from datetime import datetime
import csv
import ipaddress


def snmp_get(target, communityname, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    """
    Constuctor function for fetching OID data from device.

    @params:
        target            - Required  : IP address of the device (Str)
        communityname     - Required  : SNMP community name (Str)
        port              - Optional  : UDP port for SNMP request (Int)
        engine            - Optional  : SNMP engine for request, from pysnmp hlapi (Obj)
        context           - Optional  : SNMP context data for request, from pysnmp hlapi (Obj)

    @return:
        fetch()           : Dictionary of OID values from fetch function.
    """
    model = '.1.3.6.1.2.1.1.1.0'
    serial = '.1.3.6.1.2.1.43.5.1.1.17.1'
    location = '.1.3.6.1.2.1.1.6.0'
    firmware = '.1.3.6.1.4.1.18334.1.1.1.5.5.1.1.3.1'
    hostname = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.1.1.12.1'
    domain = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.1.1.13.1'
    ip_address = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.1.1.3.1'
    subnet = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.1.1.4.1'
    gateway = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.1.1.5.1'
    primary_dns = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.2.1.3.1.1'
    secondary_dns = '.1.3.6.1.4.1.18334.1.1.2.1.5.7.1.2.1.3.1.2'

    oids = [model, serial, location, firmware, hostname, domain, ip_address, subnet, gateway, primary_dns, secondary_dns]

    handler = hlapi.getCmd(
        engine,
        communityname,
        hlapi.UdpTransportTarget((target, port)),
        context,
        *construct_object_types(oids)
    )
    return fetch(handler, 1)


def snmp_set(target, value_pairs, communityname, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    """
    Constuctor function for setting OID data to device. Values set are returned back.

    @params:
        target            - Required  : IP address of the device (Str)
        value_pairs       - Required  : Dictionary of OIDs and values, where OID is the key. (Dict)
        communityname     - Required  : SNMP community name (Str)
        port              - Optional  : UDP port for SNMP request (Int)
        engine            - Optional  : SNMP engine for request, from pysnmp hlapi (Obj)
        context           - Optional  : SNMP context data for request, from pysnmp hlapi (Obj)

    @return:
        fetch()           : Dictionary of OID values from fetch function.
    """
    handler = hlapi.setCmd(
        engine,
        communityname,
        hlapi.UdpTransportTarget((target, port)),
        context,
        *construct_value_pairs(value_pairs)
    )
    return fetch(handler, 1)


def to_csv(row, filename='Device_data.csv'):
    """
    Writes list list of dictionary values to csv file.

    @params:
        row             - Required  : list of dictionary values (list dict).
        filename        - Optional  : filename and realtive or absolute save path for device data csv. (Str)
    """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['model',
                         'serial',
                         'location',
                         'firmware',
                         'hostname',
                         'domain',
                         'ip_address',
                         'subnet',
                         'gateway',
                         'primary_dns',
                         'secondary_dns'])
        for r in row:
            writer.writerow(r.values())


def construct_object_types(list_of_oids):
    object_types = []
    for oid in list_of_oids:
        object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
    return object_types


def construct_value_pairs(list_of_pairs):
    pairs = []
    for key, value in list_of_pairs.items():
        pairs.append(hlapi.ObjectType(hlapi.ObjectIdentity(key), value))
    return pairs


def cast(value):
    """
    Convert OID value to correct data type.

    @params:
        value   - Required  : current iteration.

    @return:
        value               : Returns int, float, PrettyPrint, Str depending on OID value given.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        try:
            return float(value)
        except (ValueError, TypeError):
            try:
                return rfc1902.IpAddress.prettyPrint(value)
            except (ValueError, TypeError):
                return str(value)
    return value


def fetch(handler, count):
    """
    Get OIDs data from device.

    @params:
        handler     - Required  : current iteration (Int)
        count       - Required  : total iterations (Int)

    @return:
        result                  : Dictionary of OID values.
    """
    result = {}
    for i in range(count):
        try:
            error_indication, error_status, error_index, var_binds = next(handler)
            if not error_indication and not error_status:
                items = {}
                for var_bind in var_binds:
                    items[str(var_bind[0])] = cast(var_bind[1])
                result = items
            else:
                if (error_status != 0):
                    print(error_status)
        except Exception as e:
            print(e)
    return result


def ping_check(host):
    """
    Ping given IP address. One try and 500 ms timeout.

    @params:
        host   - Required  : IP address of the device (Str)

    @return:
        boolean            : True if response received otherwise false.
    """
    response = ping(host, count=1, timeout=0.5)

    for res in response._responses:
        if (res.success):
            return True
    return False


def ping_sweep(start, end, silent=False):
    """
    Scan network range for devices with ping.

    @params:
        start     - Required  : start ip address of the range (Str)
        end       - Required  : end ip address of the range (Str)

    @return:
        active_hosts          : List of ip adresses that responded to ping.
    """
    start_time = datetime.now()
    start_ip = int(ipaddress.IPv4Address(start))
    end_ip = int(ipaddress.IPv4Address(end))
    active_hosts = []
    count = 0

    print('Scanning devices...')
    for ip in progressBar(range(start_ip, end_ip + 1), prefix='|'):
        address = str(ipaddress.IPv4Address(ip))
        if (ping_check(address)):
            count += 1
            active_hosts.append(address)
    if (not silent):
        print(f'{count} active hosts found: {active_hosts}')

        end_time = datetime.now()
        print(f'Scanning devices from network copleted in: {end_time - start_time}\n')

    return active_hosts


def get_device_info(hosts, communityname, silent=False):
    """
    Get oid values from device.

    @params:
        hosts           - Required  : list of IP adresses (Str list)
        communityname   - Required  : SNMP community name (Str)

    @return:
        results         : List of dictionary containing oids and values (list dict)
    """
    results = []

    def get_data():
        data = snmp_get(host, communityname)
        if (data is not None and len(data) > 0):
            data['response_address'] = host
            results.append(data)

    if (not silent):
        print('Starting to collect information...')

        for host in progressBar(hosts):
            get_data()

    else:
        print('Looking for serialnumber...')
        for host in hosts:
            get_data()

    return results


def get_device_by_serial(serialnumber, active_hosts, community):
    dataset = get_device_info(active_hosts, community, True)
    for data in dataset:
        if (data['1.3.6.1.2.1.43.5.1.1.17.1'] == serialnumber):
            return data
    return []


def progressBar(iterable, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar.

    @params:
        iterable    - Required  : current iteration (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    total = len(iterable)
    _prefix = prefix

    # Progress Bar Printing Function
    def printProgressBar(iteration):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{_prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Initial Call
    printProgressBar(0)
    # Update Progress Bar
    for i, item in enumerate(iterable):
        if (prefix == ''):
            _prefix = item
        printProgressBar(i)
        yield item
        printProgressBar(i + 1)
    # Print New Line on Complete
    print()


def help():
    """
    Prints help to terminal

    """

    print("___  ___ _   __                            ")
    print("|  \\/  || | / /                            ")
    print("| .  . || |/ /   ___ _ __  _ __ ___  _ __  ")
    print("| |\\/| ||    \\  / __| '_ \\| '_ ` _ \\| '_ \\ ")
    print("| |  | || |\\  \\ \\__ \\ | | | | | | | | |_) |")
    print("\\_|  |_/\\_| \\_/ |___/_| |_|_| |_| |_| .__/ ")
    print("                                    | |    ")
    print("                                    |_|    ")

    print("\nDESCRIPTION: ")
    print("Get MFP device information from device via SNMP.")
    print("Data returned from device:")
    print("model, serialnumber, location, firmware, hostname, domain, ip_address, subnet, gateway, primary_dns, secondary_dns")

    print("\nUSAGE: ")
    print(" -ip or --ip_address")
    print("  Get singe device information, data is returned to csv file.")

    print("\n -ipr or --ip_range")
    print("  Scan IP range for devices and return information to csv file.")

    print("\n -c or --community")
    print("  OPTIONAL: Change SNMP community name for query. Default value is public.")

    print("\n -s or --set")
    print("  Write new value to OID in device.")

    print("\nEXAMPLE: ")
    print(" -ip 192.168.1.10")
    print(" -ipr 192.168.1.1 192.168.1.255")
    print(" -ipr 192.168.1.0/24")
    print(" --community private --ip_address 192.168.1.10")
    print('-ip 192.168.1.10 --set .1.3.6.1.2.1.1.6.0 "new location"')


def main():
    # get command line arguments

    execute = False
    address = None
    write = False
    oid = None
    value = None
    start_ip = None
    end_ip = None
    serialnumber = None
    community = hlapi.CommunityData('public')

    for index, arg in enumerate(argv):
        index += 1
        if (arg.lower() == "-h" or arg == "/?" or arg.lower() == "--help"):
            help()
            raise SystemExit

        if (arg.lower() == "-c" or arg.lower() == "--community"):
            try:
                print(f'community name changed: {argv[index]}')
                community = hlapi.CommunityData(argv[index])
            except IndexError:
                print('\nERROR: Incorrect use of community. No value given for one or more required parameters.\n')
                print('EXAMPLE: \n-c public')
                raise SystemExit

        if (arg.lower() == "-ip" or arg.lower() == "--ip_address"):
            try:
                address = argv[index]
            except IndexError:
                print('\nERROR: Incorrect use of ip address. No value given for one or more required parameters.\n')
                print('EXAMPLE: \n-ip 192.168.1.10')
                raise SystemExit
            execute = True

        if (arg.lower() == "-ipr" or arg.lower() == "--ip_range"):
            try:
                if (len(argv[index].rsplit('/')) > 1):
                    start_ip = ipaddress.IPv4Network(argv[index]).network_address
                    end_ip = ipaddress.IPv4Network(argv[index]).broadcast_address
                else:
                    start_ip = argv[index]
                    end_ip = argv[index + 1]
            except IndexError:
                print('\nERROR: Incorrect use of ip range. Use CIDR notation or give two ip addresses separeted by space.')
                print('EXAMPLE: \n-ipr 192.168.1.1 192.168.1.10\n-ipr 192.168.1.0/24')
                raise SystemExit
            execute = True

        if (arg.lower() == "-s" or arg.lower() == "--set"):
            try:
                oid = argv[index]
                value = argv[index + 1]
            except IndexError:
                print('\nERROR: Incorrect use of set. Give OID and value separeted by space.\n')
                print('EXAMPLE: \n-ip 192.168.1.10 --set .1.3.6.1.2.1.1.6.0 "new location"')
                raise SystemExit
            write = True
            execute = True

        if (arg.lower() == "-f" or arg.lower() == "--find_serial"):
            try:
                serialnumber = argv[index]
            except IndexError:
                print('\nERROR: Incorrect use of find serial. No value given for one or more required parameters.')
                print('EXAMPLE: \n-f AA2K027512345 -ipr 192.168.1.1 192.168.1.10\n-f AA2K027512345 -ipr 192.168.1.0/24')
                raise SystemExit
            execute = True

    if (address is None and execute is False):
        help()
        raise SystemExit

    if (write and oid is not None and value is not None):
        print(f'Connecting to address: {address}')
        dataset = {}
        dataset[oid] = value
        if (address is None):
            print('\nERROR: IP address not given. --set also requires use of --ip_address or -ip\n')
            print('EXAMPLE: \n-ip_address 192.168.1.10 --set .1.3.6.1.2.1.1.6.0 "new location"')
            raise SystemExit
        results = snmp_set(address, dataset, community)

        if (len(results) != 0):
            print('Values successfully writen to device.')
            print(results)
        else:
            print('Were not able to write data to device. Please check OID and communityname.')

    if (write is False and address is not None):
        print(f'Connecting to address: {address}')
        print(snmp_get(address, community))

    if (execute):
        if (serialnumber is not None and start_ip is None or end_ip is None):
            print('\nERROR: IP address range not given. --find_serial also requires use of --ip_range or -ipr\n')
            print('EXAMPLE: \n-f AA2K027512345 -ipr 192.168.1.1 192.168.1.10\n-f AA2K027512345 -ipr 192.168.1.0/24')
            raise SystemExit
        if (start_ip is not None and end_ip is not None):
            if (serialnumber is not None):
                active = ping_sweep(start_ip, end_ip, silent=True)
            else:
                active = ping_sweep(start_ip, end_ip)

        if (len(active) > 0):
            data = []
            if (serialnumber is not None):
                result = get_device_by_serial(serialnumber, active, community)
            else:
                data = get_device_info(active, community)
        else:
            raise SystemExit
        if (len(data) > 0):
            difference = len(active) - len(data)
            if (difference != 0):
                print(f'Data received from {len(data)} device(s). Were not able to get any data from {difference} device(s).')
            else:
                print(f'Data received from {len(data)} device(s).')
            to_csv(data)
        elif (len(result) > 0):
            print(f'\nFound device with serialnumber {serialnumber} from address {result["response_address"]}.\n')
        elif (len(result) == 0):
            print(f'\nNo device found with serialnumber {serialnumber}.\n')
        else:
            print(f'Were not able to get any data from {len(active)} device(s).')
            print(active)


if (__name__ == "__main__"):
    try:
        start_time = datetime.now()
        main()
        end_time = datetime.now()
        print(f'Program copleted in: {end_time - start_time}')
    except Exception as e:
        end_time = datetime.now()
        print(f'Scanning failed in: {end_time - start_time}')
        print(e)
