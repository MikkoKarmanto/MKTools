# MKTools

 Tools for Konica Minolta devices and for SafeQ

```Python
___  ___ _   __
|  \/  || | / /
| .  . || |/ /   _______ ______ __
| |\/| ||    \  / __| '_ \| '_`_ \| '_\
| |  | || |\  \ \__ \ | | | | | | | | |_) |
\_|  |_/\_| \_/ |___/_| |_|_| |_| |_| .__/
                                    | |
                                    |_|
```

Get MFP device information from device via SNMP.
Data returned from device:
model, serialnumber, location, firmware, hostname, domain, ip_address, subnet, gateway, primary_dns, secondary_dns

## USAGE

* -ip or --ip_address

...Get singe device information, data is returned to csv file.

* -ipr or --ip_range

...Scan IP range for devices and return information to csv file.

* -c or --community

...OPTIONAL: Change SNMP community name for query. Default value is public

## EXAMPLE

* -ip 192.168.1.10
* -ipr 192.168.1.1 192.168.1.255
* --community private --ip_address 192.168.1.10
