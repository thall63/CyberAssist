# Hash
Hash is GUI interface for hashing files and submitting file hashes to Virus Total.

![](hash_screenshot.jpg)

## Install
Simply install PyQt6 into your python environment, *pip install PyQt6*. The main package "hash.py" may be compiled to run conventiently as a single file executable. I recommend "pyinstaller" for creating a single "exe" file that runs on Windows environments. The *requirements.txt* file lists the individual PyQt6 packages and versions used. All other imports are Python "*built-ins*". A compiled "release" is also planned with the first stable version of the code. Check the CyberAssist Project github page for the compiled release. Place the executable anywhere on your Windows 10 or higher PC and doubleclick.

## License
See https://github.com/thall63/CyberAssist/blob/main/LICENSE

## Features
- Hash is a file hashing tool with extras
- Create a hash of any file. Many hash types are available or generate all hashes. Hash types include md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, and sha3_512
- Submit any hash of type md5, sha-1 or sha-256 to Virus Total (Requires Virus Total personal API token)
- Returns Virus Total reputaion and vendors who have flagged the hash value as malicious