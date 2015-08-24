# wmi-samba
Source code from http://www.openvas.org/download/wmi with a couple of extras

To make go to the root and "make"

To only build wmic without going through the whole autoconf cycle:
Change to: ./Samba/source
"make bin/wmic"
Example run: ./bin/wmic -U int-link/whites%mypass //vostro400-vm "select * from Win32_Product"
