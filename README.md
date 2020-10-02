# ARP-spoofing
A linux script to automatically ARP spoof a device and gain a man in the middle position. Simply run the script and it will try and detect what subnet you are on (only supports 192.168.0.0/24 and 10.0.2.0/24 so far) or you can specify your own subnet to scan using the `-t` flag. You can then pick a target from the list of devices found and the script will start sending ARP spoof packets to gain a man in the middle position (uses your default gateway as the router).

**Example of script running:**

![Example](https://i.imgur.com/bcwwF8U.png)

> Don't use this script with malintent or to break any laws!
