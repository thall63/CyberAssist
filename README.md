# CyberAssist Project  
Cyber Analysts need tools. The CyberAssist Project is a collection of deskside tools designed for cyber analysts. Each tool is a gui interface with limited but powerful capability. Because cyber analysts arrive from all types of unique technical backgrounds, there are naturally knowledge gaps. The first CyberAssist Project release is "IP Subnet Helper" for those less familair with the practice of IP subnetting.  

## Coding
All tools are coded with Python and PyQT6. PyQT6 was selected as a GUI Framework for it's friendly and fast coding attributes and it's easy to use implementation of PyQT Threads. PyQT Threads improves performance for intense calculations. When you are calculating a large IP subnet, workers will send your task to multiple threads and run the task in the background. This feature means that the main application will not "freeze" because the apps main event loop is still free to process button clicks, be dragged to a new location. When a task is being processed in this way, the button for submitting the task will be disabled until the task is completed to avoid duplication of the same task and provide the fastest return of data possible. When complete the submission feature is re-enabled for use.

## License
You may use and even modify the code for personal use. If you are working for any employer, use is not restricted but the code cannot be modified with the owners explicit, written permisison. (See git License for details)

## Available Apps
- IP Subnet Helper
  - IP subnet calculation including subnet range, default gateway and a count of the IP contained in the subnet
  - Provides idenfication of global, private, multicast, reserved, unspecified, loopback and link local IP addresses
  - Collapse multiple subnets into a single supernet
  - Scrape valid IP Addresses from unstructured text

## Coming Soon
- Maybe you will leave comments and tell me!!!
