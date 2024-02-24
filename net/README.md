# Net
Net is GUI interface for subnetting, summarizing and scraping IP addresses. IPv4 and IPv6 options are available.

![](net_screenshot.jpg)

## Operating System Support and requirements
Net runs on Windows 10 or higher. Net may run on older versions of Windows but it is not tested or supported. There are plans to port Net with Kivi to make it cross-platform and mobile friendly in the future.

## Install
Simply install PyQt6 into your python environment, *pip install PyQt6*. The main package "net.py" may be compiled to run conventiently as a single file executable. I recommend "pyinstaller" for creating a single "exe" file that runs on Windows environments. The *requirements.txt* file lists the individual PyQt6 packages and versions used. All other imports are Python "*built-ins*". A compiled "release" is also planned with the first stable version of the code. Check the CyberAssist Project github page for the compiled release. Place the executable anywhere on your Windows 10 or higher PC and doubleclick.

## License
See https://github.com/thall63/CyberAssist/blob/main/LICENSE

## Features
- Net
  - Net is an IP subnet calculator with extras
  - IPv4 subnet calculation includes subnet range, default gateway and a count of the total nubmer of hosts
  - IPv6 subnet calculation includes range the first and last host of the subnet and the total number of hosts
  - User defined network prefix
  - IPv4 and IPv6 calculations include idenfication of global, private, multicast, reserved, unspecified, loopback and link local IP addresses
  - Collapses multiple, contiguous IPv4 subnets into the largest subnet possible
  - Collapses multiple, contingous IPv6 prefixes into the largest possible summary
  - Scrapes valid IP Addresses from unstructured text. IP addresses may be both IPv4 and IPv6 within an unstructured text. The scrape functionality considers only "full matches". IP addresses must be separated from other text by at least a single space.
  - Sun or Moon UI Presentation

