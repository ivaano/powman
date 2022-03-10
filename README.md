UPS Power Manager

Script to turn off safely any device after a power loss, optionally
turning them back on if the device support wol.


This script uses nut, nut(https://networkupstools.org) already provides upssched to do
what this script does, but there is not much flexibility
if I want to use a parameter other than the battery.runtime,
to power off a device or send notifications, its to do it with 
upssched configuration.

This is running on raspbian 10, and I shutdown a Nas after 5 minutes of power loss
and I shutoff an esxi when battery is less than 25%


