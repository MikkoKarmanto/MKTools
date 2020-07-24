from pysnmp import hlapi
from pysnmp.proto import rfc1902
from sys import argv
from pythonping import ping
from datetime import datetime
import csv


def get(target, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    """
    Constuctor function for fetching OID data from device.

    @params:
        target          - Required  : IP address of the device (Str)
        credentials     - Required  : SNMP community name (Str)
        port            - Optional  : UDP port for SNMP request (Int)
        engine          - Optional  : SNMP engine for request, from pysnmp hlapi (Obj)
        context         - Optional  : SNMP context data for request, from pysnmp hlapi (Obj)

    @return:
        fetch()                     : Dictionary of OID values from fetch function.
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
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        *construct_object_types(oids)
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
                print(f'Got SNMP error: {error_indication}')
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


def ping_sweep(start, end):
    """
    Scan network range for devices with ping.

    @params:
        start     - Required  : start ip address of the range (Str)
        end       - Required  : end ip address of the range (Str)

    @return:
        active_hosts          : List of ip adresses that responded to ping.
    """
    start_time = datetime.now()
    start_ip = start.split('.')
    end_ip = end.split('.')

    if (len(start_ip) == 4 and len(end_ip) == 4):
        print('Scanning devices...')
        active_hosts = []
        count = 0
        for ip in progressBar(range(int(start_ip[3]), int(end_ip[3]) + 1)):
            address = None
            for num in start_ip[:-1]:
                if (address is None):
                    address = num
                else:
                    address += f'.{num}'
            address += f'.{str(ip)}'
            if (ping_check(address)):
                count += 1
                active_hosts.append(address)
        print(f'{count} active hosts found: {active_hosts}')
    else:
        print('IP in wrong format.')
    end_time = datetime.now()

    print(f'Scanning devices from network copleted in: {end_time - start_time}\n')

    return active_hosts


def get_device_info(hosts, credentials):
    """
    Get oid values from device.

    @params:
        hosts         - Required  : list of IP adresses (Str list)
        credentials   - Required  : SNMP community name (Str)

    @return:
        results      : List of dictionary containing oids and values (list dict)
    """
    print('Starting to collect information...')
    results = []
    for host in hosts:
        print(f'Getting device information from host: {host}')
        data = get(host, credentials)
        if (data is not None and len(data) > 0):
            print('Storing information.')
            results.append(data)
        else:
            print('Device did not return any data.')
    return results


def progressBar(iterable, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar.

    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    total = len(iterable)

    # Progress Bar Printing Function
    def printProgressBar(iteration):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Initial Call
    printProgressBar(0)
    # Update Progress Bar
    for i, item in enumerate(iterable):
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

    print("\nGet MFP device information from device via SNMP.")
    print("Data returned from device:")
    print("model, serialnumber, location, firmware, hostname, domain, ip_address, subnet, gateway, primary_dns, secondary_dns")

    print("\nUSAGE: ")
    print(" -ip or --ip_address")
    print("  Get singe device information, data is returned to csv file.")

    print("\n -ipr or --ip_range")
    print("  Scan IP range for devices and return information to csv file.")

    print("\n -c or --community")
    print("  OPTIONAL: Change SNMP community name for query. Default value is public")

    print("\nEXAMPLE: ")
    print(" -ip 192.168.1.10")
    print(" -ipr 192.168.1.1 192.168.1.255")
    print(" --community private --ip_address 192.168.1.10")


def main():
    # get command line arguments

    community = hlapi.CommunityData('public')
    for index, arg in enumerate(argv):
        index += 1
        if (arg.lower() == "-h" or arg == "/?" or arg.lower() == "--help"):
            help()
            raise SystemExit

        if (arg.lower() == "-c" or arg.lower() == "--community"):
            print(f'community name changed: {argv[index]}')
            community = hlapi.CommunityData(argv[index])

        if (arg.lower() == "-ip" or arg.lower() == "--ip_address"):
            print(f'Connecting to address: {argv[index]}')
            print(get(argv[index], community))

        if (arg.lower() == "-ipr" or arg.lower() == "--ip_range"):
            active = ping_sweep(argv[index], argv[index + 1])
            data = get_device_info(active, community)
            to_csv(data)

        if (arg.lower() == "-t" or arg.lower() == "--test"):
            active = ping_sweep('192.168.1.170', '192.168.1.175')
            get_device_info(active, community)


if (__name__ == "__main__"):
    try:
        start_time = datetime.now()
        main()
        end_time = datetime.now()
        print(f'Scanning copleted in: {end_time - start_time}')
    except Exception as e:
        end_time = datetime.now()
        print(f'Scanning failed in: {end_time - start_time}')
        print(e)
