#Copyright (c) 2014, Hewlett-Packard Development Company, L.P.
#
# Sample UEFI shell startup.nsh script downloaded from an HTTP or FTP URL.
#
# This script is downloaded and executed at the time of launching
# the Embedded UEFI shell on HP Server platforms. This shell script
# demonstrates the usage of HP value added commands in the embedded
# UEFI shell to download the necessary OS files to a BIOS RAMDISK,
# and boot it.
#
# Pre-requisites for launching this script:
#  1. Pre-Boot Network Settings:
#     a. Pre-Boot Network Interface=Auto (Default) [OR] select an available NIC.
#     b. DHCPv4=Enabled (Default) [OR]
#        set IPv4 Address, Subnet Mask, Gateway, Primary, Secondary DNS.
#  2. Embedded UEFI Shell:
#     a. Embedded UEFI Shell=Enabled
#     b. UEFI Shell Script Auto-Start=Enabled
#     c. Shell Auto-Start Script Location=Auto or "Network Location"
#     d. Network Location for Shell Auto-Start Script.
#  3. Set One time boot to "Embedded UEFI Shell".
#

@echo -off

#
# Setup the environment variables. All of them are created as volatile.
#

#
# The volume label for the RAMDISK.
#
set -v VolumeLabel MYRAMDISK

#
# variable to store the file system index that we will loop
# to determine the FS<x> number for the RAMDISK we create.
	#
set -v FsIndex 0

#
# variable to store the output string of the ramdisk -c command.
# Successful creation of RAMDISK will give the following output:
# "RAM disk 'FSx:' created successfully." where x=0,1,2,...
#
set -v RamDiskStr 0

#
# size of the RAMDISK in MegaBytes (MB).
#
set -v RamDiskSize 1024

#
# Server URL hosting the OS loader and images.
# Can be HTTP or FTP. Names or IP addresses are allowed.
# Ensure DNS service is available and configured (see pre-requisites)
# when server names are used.
#

#
# Files to be downloaded
#
set -v grubx64.efi {{uefi_bootfile}}
set -v kernel {{kernel}}
set -v ramdisk {{ramdisk}}
set -v grub {{grub}}

#
# Step 1. Create our RAMDISK to store the downloaded OS programs.
#
echo "Creating a RAM Disk to save downloaded files..."
ramdisk -c -s %RamDiskSize% -v %VolumeLabel% -t F32 >v RamDiskStr
if %lasterror% ne 0x0 then
  echo "Cannot create a RAMDISK of size %RamDiskSize%."
  goto EXITSCRIPT
endif
echo "RAM Disk with Volume Label %VolumeLabel% created successfully."

#
# Step2: Check each word in the output (RamDiskStr) and see if it matches
# the FSx: pattern. The newly created RAMDISK will be FS1: or higher.
# Here we check upto FS3: (the inner for loop), but a larger limit
# may be used in case many other file systems already exist before
# the creation of this RAMDISK. The FS for the RAMDISK is found when the
# FsIndex matches the FS<x> in RamDiskStr. Change the working directory
# to FS<FsIndex>:, so all our downloads get saved there.
#
# FS0: is ignored. In the worst case, when no other usable
# file system is present, FS0: will map to the file system
# that this script is executing from, which we do not care.
#
#
for %a in %RamDiskStr%
  for %b run (1 10)
    set -v FsIndex %b
    if 'FS%FsIndex%:' == %a then
      FS%FsIndex%:
      goto RDFOUND
    endif
  endfor
endfor

#
# The newly created RAMDISK cannot be found, ideally
# shouldn't come here!
#
echo "RAMDISK with Volume Label %VolumeLabel% not found!"
goto EXITSCRIPT

#
# The RAMDISK FS<x> has been found and we are in the
# RAMDISK's root folder.
#
:RDFOUND
echo "RAMDISK with Volume Label %VolumeLabel% found at FS%FsIndex%:."
mkdir boot
cd boot
mkdir efi
cd efi
#
# Step3: Download the required files into the RAMDISK.
#
echo "Downloading %DownloadFile1% (File 1 of 3...)"
webclient -g %grubx64.efi% -o grubx64.efi.signed
if %lasterror% ne 0x0 then
  goto EXITSCRIPT
endif

echo "Downloading %DownloadFile2% (File 2 of 3...)"
webclient -g %kernel% -o kernel
if %lasterror% ne 0x0 then
  goto EXITSCRIPT
endif

echo "Downloading %DownloadFile3% (File 3 of 3...)"
webclient -g %ramdisk% -o ramdisk
if %lasterror% ne 0x0 then
  goto EXITSCRIPT
endif

#
# Step4: Launch the boot loader.
#
cd ..
cd ..

echo "Creating a new directory grub"
mkdir grub
cd grub
echo "Downloading %grub%"
webclient -g %grub%
if %lasterror% ne 0x0 then
  goto EXITSCRIPT
endif

cd ..
cd boot
cd efi

echo "Starting the OS..."
grubx64.efi.signed

#
# Reached here only if the downloads and booting failed.
#
:EXITSCRIPT
echo "Exiting Script."

@echo -on
