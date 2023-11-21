# CyberAssist Project  
Cyber Analysts need tools. The CyberAssist Project is a collection of deskside tools designed for cyber analysts. Each tool is a gui interface with powerful capability. The first **CyberAssist Project** release is "*Net*", an ip subnet helper for those less familair with the practice of IP subnetting.  

## Coding
All tools are coded with **Python** and **PyQT6**. PyQT6 was selected as a GUI Framework for it's friendly and fast coding attributes and it's easy to use implementation of PyQT Threads. PyQT implementation of threads improves performance for processing intense calculations. When you are calculating large IP subnets, workers will send your task to multiple threads and run the task in the background. This feature means that the main application will not "freeze" because the apps main event loop is still free to process user actions such as button clicks or dragging the main app to a new location on the desktop. When a task is being processed in this way, the button for submitting the task will be disabled until the task is completed to avoid duplication of the same task and provide the fastest return of data possible. When the task is completed, the button is re-enabled for use. This code uses uses the Python "*ipaddress*" module to perform ip subnetting calculations.

## Cyber Community
I maintain the Cyber Assist Project for the Cyber Community in an effort to promote the legal use and sharing of functional cyber security tools. Maintaining a small set of local, trusted tools prevents the download of weaponized trojans and provides the underserved cyber analysts with a free, essential resource. I am hopeful that your investigations are assisted, learning results from their use and that these tools are improved further by community contributions.

## Install
Simply install PyQt6 into your python environment, *pip install PyQt6*. The main package "net.py" may be compiled to run conventiently as a single file executable. I recommend "pyinstaller" for creating a single "exe" file that runs on Windows environments. The *requirements.txt* file lists the individual PyQt6 packages and versions used. All other imports are Python "*built-ins*".

## License
See https://github.com/thall63/CyberAssist/blob/main/LICENSE

## Available Apps
- Net
  - Net is an IP subnet calculator with extras
  - IP subnet calculation including subnet range, default gateway and a count of the IP contained in the subnet
  - User defined CIDR mask
  - Provides idenfication of global, private, multicast, reserved, unspecified, loopback and link local IP addresses
  - Collapses multiple, contiguous subnets into the largest subnet possible
  - Scrapes valid IP Addresses from unstructured text

- Hash
  - Upcomming tool that will create a variety of popular hash values for a file.

## Coming Soon
- Maybe you will leave comments and tell me!!!
