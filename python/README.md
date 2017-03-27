# Deduplication Tool (Python)

This tool is a simple implementation for reading duplicate data and storing the file slack of each found file.

## Requirements

With the exception of the AFF4 support no additional libraries have to be installed. For the AFF4 support please install the following package(s):

* pyaff4 (0.23+)
 
## Configuration

To create a new configuration:
```python
python main.py --generateconfig "/path/to/writable/location/myconfigname.py"
```
 
To use an existing configuration outside of the install dir:
```python
python main.py --useconfig "/path/to/writable/location/myconfigname.py"
```
 
### Override Devices via Arguments
Instead of providing different configurations for different use cases you can override devices via arguments:
```python
python main.py --useconfig '/path/to/config/configname.py' --device (1,'Device Name 1','/mnt/dev1') (2,'Device Name 2','/mnt/dev2')
```
This will load the devices (if specified) and settings from your configuration and add/override the devices.
To override a device simply specify a device with the same id.
 
## Help

```python
python main.py --help
```