# Find and validate IP with regex
import re
# Use ipaddress module to validate IP if needed, also use for CIDR notation
import ipaddress

# Compile regex patterns
ipv4_addr = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ipv6_standard = re.compile('(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', re.IGNORECASE)
ipv6_compressed = re.compile('(([A-F0-9]{1,4}:){7}[A-F0-9]{1,4}|(?=([A-F0-9]{0,4}:){0,7}[A-F0-9]{0,4}(?![:.\w]))(([0-9A-F]{1,4}:){1,7}|:)((:[0-9A-F]{1,4}){1,7}|:)|([A-F0-9]{1,4}:){7}:|:(:[A-F0-9]{1,4}){7})', re.IGNORECASE)
ipv6_mixed = re.compile('(?:[a-fA-F0-9]{1,4}:){6}(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])', re.IGNORECASE)
ipv6_mixed_compressed = re.compile('(?:(?:[a-fA-F0-9]{1,4}:){6}|(?=(?:[a-fA-F0-9]{0,4}:){0,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3})(([a-fA-F0-9]{1,4}:){0,5}|:)((:[a-fA-F0-9]{1,4}){1,5}:|:)|::(?:[a-fA-F0-9]{1,4}:){5})(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])', re.IGNORECASE)

# Test strings
ipv4 = '192.168.0.0  172.42.5.7  999.1.1.1 4.5.6.255 10.1.1.3 3.4.5.0 666.7.8.9'
standard = 'jello A000:0040:0020:0010:0B00:0abc:0007:0def jello B000:0040:0020:0010:0B00:0abc:0007:0def A000:0040:0020:0010:0B00:0abc:0007:ffe0   A000:0040:0020:0010:0B00:0abc:0007:ffe*'
compressed = 'A000::B00:A:0007:0DEF junk B000::B00:A:0007:0DEF  B000:B00:A555:0007::0DEF   B000:B00::A555:0007::0DEF    B000:B00::A555:0007::0DEF9'
# compressed = 'A000::B00:A:0007:0DEF,junk,B000::B00:A:0007:0DEF,B000:B00:A555:0007::0DEF,B000:B00::A555:0007::0DEF,B000:B00::A555:0007::0DEF9'
mixed = '1762:10:05:a0:0:B03:127.32.67.15 more junk 1962:10:05:a0:0:B03:127.32.67.15   1962:10:05:a0:0:B03:192.32.67.15  1962:10:05:a0:0:B03:192.32.999.15  1962:10::05:a0:0:B03:192.32.9.15'
mixed_compressed = '1762:10:05::127.32.67.15 and even more junk 1962:10::05:127.32.67.15 1762:10::05:10.32.67.15  1762:10::05::10.32.67.15   1762:10::05:10.32.67.999  1762:10::05::10.32.67.9'

all_ip = '''
# Test strings
ipv4 = 192.168.0.0  172.42.5.7  999.1.1.1 4.5.6.255 10.1.1.3 3.4.5.0 666.7.8.9
standard = jello A000:0040:0020:0010:0B00:0abc:0007:0def jello B000:0040:0020:0010:0B00:0abc:0007:0def A000:0040:0020:0010:0B00:0abc:0007:ffe0   A000:0040:0020:0010:0B00:0abc:0007:ffe*
compressed = A000::B00:A:0007:0DEF junk B000::B00:A:0007:0DEF  B000:B00:A555:0007::0DEF   B000:B00::A555:0007::0DEF    B000:B00::A555:0007::0DEF9
# compressed = A000::B00:A:0007:0DEF,junk,B000::B00:A:0007:0DEF,B000:B00:A555:0007::0DEF,B000:B00::A555:0007::0DEF,B000:B00::A555:0007::0DEF9
mixed = 1762:10:05:a0:0:B03:127.32.67.15 more junk 1962:10:05:a0:0:B03:127.32.67.15   1962:10:05:a0:0:B03:192.32.67.15  1962:10:05:a0:0:B03:192.32.999.15  1962:10::05:a0:0:B03:192.32.9.15
mixed_compressed = 1762:10:05::127.32.67.15 and even more junk 1962:10::05:127.32.67.15 1762:10::05:10.32.67.15  1762:10::05::10.32.67.15
'''
# get the delimiter
splitter = str(input('Enter a character (, ; | or press enter for space delimited) to split the text: '))
if splitter == '':
    splitter = ' '

# working - returns all IPv4 matches
ipv4_list = []
split_list = all_ip.split(splitter)
for item in split_list:
    ipv4_result = ipv4_addr.fullmatch(item)
    if ipv4_result:
        ipv4_list.append(ipv4_result.group())
print('IPv4 all matches')
for item in ipv4_list:
    print(item)
print()

# working - returns all standard IPv6 matches
standard_list = []
split_list = all_ip.split(splitter)
for item in split_list:
    std_result = ipv6_standard.fullmatch(item)
    if std_result:
        standard_list.append(std_result.group())
print('Standard all matches')
for item in standard_list:
    print(item)
print()

# working - returns all IPv6 compressed matches
compressed_list = []
split_list = all_ip.split(splitter)
for item in split_list:
    compressed_result = ipv6_compressed.fullmatch(item)
    if compressed_result:
        compressed_list.append(compressed_result.group())
print('Compressed all matches')
for item in compressed_list:
    print(item)
print()

# working - returns all IPv6 mixed notation matches
mixed_notation_list = []    
split_list = all_ip.split(splitter)
for item in split_list:
    mixed_result = ipv6_mixed.fullmatch(item)
    if mixed_result:
        mixed_notation_list.append(mixed_result.group())
print('Mixed notation all matches')
for item in mixed_notation_list:
    print(item)
print()

# working - returns all IPv6 mixed compressed matches
mixed_compressed_list = []
split_list = all_ip.split(splitter)
for item in split_list:
    mixed_compressed_result = ipv6_mixed_compressed.fullmatch(item)
    if mixed_compressed_result:
        mixed_compressed_list.append(mixed_compressed_result.group())
print('Mixed compressed all matches')
for item in mixed_compressed_list:
    print(item)
print()
