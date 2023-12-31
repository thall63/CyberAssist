# Net
Net is GUI interface for subnetting, summarizing and scraping IP addresses. IPv4 and IPv6 options are available.

## Install
Simply install PyQt6 into your python environment, *pip install PyQt6*. The main package "net.py" may be compiled to run conventiently as a single file executable. I recommend "pyinstaller" for creating a single "exe" file that runs on Windows environments. The *requirements.txt* file lists the individual PyQt6 packages and versions used. All other imports are Python "*built-ins*". A compiled "release" is also planned with the first stable version of the code. Check the CyberAssist Project github page for the compiled release. Place the executable anywhere on your Windows 10 or higher PC and doubleclick.

## License
See https://github.com/thall63/CyberAssist/blob/main/LICENSE

## Features
- Net is an IP subnet calculator with extras
- IP subnet calculation including subnet range, default gateway and a count of the IP contained in the subnet
- User defined CIDR mask
- Provides idenfication of global, private, multicast, reserved, unspecified, loopback and link local IP addresses
- Collapses multiple, contiguous IPv4 subnets into the largest subnet possible
- Scrapes valid IP Addresses from unstructured text. IP addresses may be both IPv4 and IPv6 within an unstructed text. IP addresses must be delimited by (space , ; or |). The scrape functionality considers only "full matches". Continuous, non-delimited text would produce valid matches from within invalid IP addresses. Therefore, non-delimited addresses cannot be matched reliably and is not supported.
