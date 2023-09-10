# CyberAssist Project  
Cyber Analysts need tools. The CyberAssist Project is a collection of deskside tools designed for cyber analysts. Each tool is a gui interface with limited but powerful capability. The first CyberAssist Project release is "IP Subnet Helper" for those less familair with the practice of IP subnetting.  

## Coding
All tools are coded with Python and PyQT6. PyQT6 was selected as a GUI Framework for it's friendly and fast coding attributes and it's easy to use implementation of PyQT Threads. PyQT Threads improves performance for processing intense calculations. When you are calculating large IP subnets, workers will send your task to multiple threads and run the task in the background. This feature means that the main application will not "freeze" because the apps main event loop is still free to process user actions such as button clicks or dragging the main app to a new location on the desktop. When a task is being processed in this way, the button for submitting the task will be disabled until the task is completed to avoid duplication of the same task and provide the fastest return of data possible. When the task is completed, the button is re-enabled for use.

## License
See https://github.com/thall63/CyberAssist/blob/main/LICENSE

## Available Apps
- IP Subnet Helper
  - IP subnet calculation including subnet range, default gateway and a count of the IP contained in the subnet
  - Provides idenfication of global, private, multicast, reserved, unspecified, loopback and link local IP addresses
  - Collapse multiple subnets into a single supernet
  - Scrape valid IP Addresses from unstructured text

## Coming Soon
- Maybe you will leave comments and tell me!!!
