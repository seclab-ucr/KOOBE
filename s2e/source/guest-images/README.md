Automated Guest Image Creation Tools
====================================

This repository contains a Makefile that allows building guest images suitable for running in S2E. The creation process
is fully automated.

It is recommended to use the ``s2e image_build`` command in order to build images instead of calling the makefiles
directly. That command ensures that the makefile is called with the right arguments and that all requirements
are met. Please refer to the S2E documentation on how to use ``s2e image_build``. This README provides a reference
in case you want to modify the image build system or add new software to existing images.

# Installation

**It is recommended to use a file system that supports copy-on-write (XFS, ZFS, or BtrFS).** The image build system
copies images for intermediate build steps and copy-on-write will save you a lot of disk space.

## Installing dependencies

```
sudo apt-get install libguestfs-tools genisoimage python-pip python-magic xz-utils docker.io p7zip-full pxz libhivex-bin fuse jigdo-file
sudo apt-get build-dep fakeroot linux-image$(uname -r)
sudo pip install jinja2

# This is necessary for guestfish to work
sudo chmod +r /boot/vmlinuz*

# Re-login after running these commands
sudo usermod -a -G docker $(whoami)
sudo usermod -a -G kvm $(whoami)
```

## Building S2E

Build and install S2E into some folder (e.g., ```/home/user/s2e/build/opt/```).
Please refer to S2E build instructions for details.

## Checking out the kernel repository
```
cd /home/user
git clone https://github.com/s2e/s2e-linux-kernel
```

## Checking out guest-images repository

```
cd /home/user
git clone https://github.com/s2e/guest-images
```

# Building images

## Linux

```
cd /home/user/guest-images

S2E_INSTALL_ROOT=/home/user/s2e/build/opt \
  S2E_LINUX_KERNELS_ROOT=/home/user/s2e-linux-kernel \
  make linux -j3
```

The build should take around 30 minutes. The images will be placed in the ```output``` directory, which looks like this:

```
./debian-8.7.1-i386/image.json
./debian-8.7.1-i386/image.raw.s2e
./debian-8.7.1-i386/image.raw.s2e.ready

./debian-8.7.1-x86_64/image.json
./debian-8.7.1-x86_64/image.raw.s2e
./debian-8.7.1-x86_64/image.raw.s2e.ready

./cgc_debian-8.7.1-i386/image.json
./cgc_debian-8.7.1-i386/image.raw.s2e
./cgc_debian-8.7.1-i386/image.raw.s2e.ready
```

Each build is composed of a json file that describes how to run the image, the image itself, as well as a "ready"
snapshot.

The build process also creates ```.stamps``` and ```.tmp-output```. The first contains stamp files to keep track of
which parts have been built, while the second contains intermediate build output (e.g., kernel images and ISO files).

## Windows

First, you need to get the ISO file for the Windows version that you want to install. You can download these images from
MSDN. The hash and the name of the ISO is specified in the  ``images.json`` file. You can use the hash to make sure that
you downloaded the right version. Place the downloaded file in the ``iso`` folder.

Do not forget to update the ``product_key`` value in the ``images.json`` file. Some versions of Windows require one
for installation (e.g., XP). Other versions install without one. You should not need to activate Windows once a snapshot
is taken (time is frozen and the guest has no Internet access). Make sure you have the required licenses to install
and use Windows this way.

The ``images.json`` file lists all Windows versions that S2E officially supports. Other images may work too but we have
not tested them. If you want to add support for new images, you may need to also update ``s2e.sys`` in the
``guest-tools`` repository in order to support the different kernels. This may not be needed if the Windows version you
need uses the exact same kernel as an already supported one. Please refer to the documentation in ``guest-tools``.

Build scripts for Windows XP and Windows 7 install service packs and updates up to January 2016 and 2020 respectively.

```
cd /home/user/guest-images

mkdir iso && cd iso
# Download Windows ISO images (e.g., from MSDN)
# See images.json for details.
wget ...
cd ..

S2E_INSTALL_ROOT=/home/user/s2e/build/opt \
  S2E_LINUX_KERNELS_ROOT=/home/user/s2e-linux-kernel \
  make windows -j3
```

## Building Microsoft Office images

This sections explains how to build Microsoft Office installation disks.
These disks must be placed in the ``iso`` folder specified with ``s2e image_build --iso-dir /path/to/isos``.
You will need 32-bit versions of Office. 64-bit versions should work too, but we did not test them.

### Office 2019

You will need to build the ISO image manually using the Microsoft Office Deployment Tools (ODT). You do not need
MSDN access for this version of Office. The scripts will install the Volume License version.

1. Find a Windows 10 machine / VM
2. Download [ODT](https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_12624-20320.exe>)
3. Run the ODT setup file, decompress it to ``C:\ODT``
4. Copy the Office 2019 configuration file located in ``Windows/install_scripts/50_office/config2019.xml`` to
   ``C:\ODT`` on the Windows machine.
4. Open ``cmd.exe``
5. Run ``md C:\Office2019``. ODT will download Office installation files into this folder
6. ``config2019.xml`` expects the download folder to be in drive ``D:\``.
   Run ``subst D:\ C:\Office2019``. This will mount the folder as ``D:\``.
   You can also edit ``config2019.xml`` to point to ``C:\Office2019`` instead.
5. Run ``C:\odt\setup.exe /download C:\ODT\config2019.xml``
6. Wait for the download to complete. Check that ``C:\Office2019`` contains the installation files.
7. Create an ISO image out of the contents of ``C:\Office2019``.
   You can do so by copying ``C:\Office2019`` to a Linux machine and then run
   ``genisoimage --iso-level 2 -flDJR -o office2019.iso Office2019/``
8. Mount the ISO file and check that the following path is present on the image:
   ``/Office/Data/16.0.10358.20061/`` (i.e., there should be an ``Office`` folder in the root of the drive).
9. Place the ISO in the ``iso`` directory.

### Office 2010, 2013, 2016

You can download the ISO files for these versions of Office from MSDN. Choose the Office Pro Plus x86 edition.
Refer to ``apps.json`` for the exact name of the ISO file to download. Place the ISO in the ``iso`` directory that
you passed to ``s2e image_build``.

If you have access to a volume license edition of Office, please choose it instead, as it will not show an activation
window every time an app is started. Except for Office 2010, you should not need product keys to install Office,
as they have a grace period of a few days before requiring activation. The image building scripts create VM snapshots
with frozen time, so expiration should not be an issue.

Office 2010 may come as a self-contained executable file on MSDN. In this case, extract this file into a folder
and create an ISO out of that folder.

### How do I tweak the Office installation?

Office installation scripts are located in ``Windows/install_scripts/50_office``. You will find the following files:
- An XML/MSP file for each supported edition. This file contains the unattended installation settings.
  The MSP file for Office 2016 is generated with the OCT tool that you can find on the ISO file.
  This tool is only available on Volume License edition.
- ``launch.bat.template`` invokes the installer.
- ``precheck.sh`` validates the ISO file.
- ``postcheck.sh`` verifies that the installation completed properly.

You can modify these files to suit your needs.

# Customizing images

## Linux

You can add additional packages to the base image by customizing the ```Linux/bootcd/preseed.cfg``` file.
Alternatively, you can modify ``Linux/s2e_home/launch.sh``. The VM has Internet access, so you can get any
additional packages you need from that script.

## Windows

Image building is divided into steps. Each step installs one or more software packages, then reboots the VM.
The last step boots the VM in TCG mode and takes a snapshot.

Each step mounts two CD drives:

1. The drive ``D:\`` contains all software packages to be installed (``00_software.iso``).
2. The drive ``E:\`` contains the scripts to install desired packages (e.g., ``05_dotnet.iso``).
   This drive is built from the folders in ``Windows/install_scripts``.

You may add additional applications to the Windows images by following these steps:

1. Add a rule to ``Makefile.windows.apps`` in order to download the installer package. The package must allow unattended
   installation (i.e., not have any dialog prompts, reboot after install must be disabled). The package will be
   automatically added to the ``00_software.iso`` disk.

2. Instead of downloading new software, you can place it in one of the installation folders
   (e.g., ``07_install_software``). If your software doesn't come with an installer, you can zip its files in an archive
   instead.

3. Modify the right ``launch.bat`` file to start the installer. In most cases, it will be
   ``07_install_software/launch.bat``. If you use a zip archive, call ``7z`` to decompress it. Refer to existing scripts
   for examples of how to do it.

The makefile detects modifications and additions to the folders in ``install_scripts``, and will automatically start the
installation from the updated step in order to minimize image build time.

Unlike Linux images, Windows VMs do not have Internet access. You must provide all additional software through ISO
images as explained above.

Note that by default, the makefile does not create intermediate copies of the guest image for each installation step in
order to save disk space. In practice, if you modify, e.g, the step ``07_install_software``, the guest image that will
be used to re-run this step will already contain changes done by subsequent steps. Read the next section to learn how to
modify this behavior.

The current image build system does not natively support software that comes on an ISO image (e.g., Microsoft Office).
You must modify the makefile to accommodate that (e.g., add an additional virtual drive with the desired software).

# Installing Windows applications

Follow these steps:

1. Get the ISO file of your app. If it does not come as an ISO file, e.g., if it is an ``exe`` or ``msi`` file,
   package that file into an ISO with the ``geniso`` tool.
2. Create an entry in ``app.json``. You can follow the same template as, e.g., Office.
3. Create a directory with installation scripts in ``Windows/install_scripts``.
   Specify that directory in the ``scripts_dir`` field in ``apps.json``.
4. Create a ``launch.bat.template`` file. This is the Windows batch file template that will run the installer.
   The template uses the Jinja2 syntax and has the following variables: ``app_name``, ``product_key``, and ``guestfs``.
   You may use the first two for configuration purposes. See the MS Office installation scripts for a complete
   example of how to use them.

    ```
    :: launch.bat.template
    :: This script is called twice: once to install the app and once after
    :: rebooting to accommodate apps that require a reboot to be usable.
    :: Therefore, we must skip the installation if we detect that the app
    :: is already installed. This is dependent on your particular app, so you
    :: should modify the following two lines accordingly.
    if exist "%SystemDrive%\Program Files (x86)\MyApp" goto end
    if exist "%SystemDrive%\Program Files\MyApp" goto end

    :: This is your installer on the ISO file. Make sure that setup.exe
    :: does not return until the installation actually completes. If you have
    :: an MSI file, run it with msiexec.
    :: The ISO file that you created for your app is mounted on D:\
    :: This installation script is located in E:\
    d:\setup.exe

    :: This must be present in order to copy the newly installed binaries to the host.
    :: S2E plugins may need to access them and some of them won't work if the
    :: binaries are missing. You should not change this line.
    c:\Python27\python.exe e:\upload_guestfs.py e:\guest_files.txt 10.0.2.100:1234 {{ guestfs }} c:\

    :end
    timeout 20
    shutdown /r /t 0
    ```

5. Create pre-check and post-check scripts. The pre-check verifies that the ISO file contains the right software
   (e.g., to avoid installing the wrong software by mistake), while the post-check verifies that the software was
   properly installed. This is typically done by looking for installed files in the ``guestfs`` directory.


# Debugging

If something goes wrong, proceed as follows:

* If something gets stuck or crashes, look at screenshots. They may contain error messages or display blocking message
  boxes. The installation process takes screenshots every few seconds and stores them in the ``.tmp-output``
  directory of each image. Run ``find . -name *.png`` to find them.

* Turn on graphics output. Open the makefile and comment out the ```GRAPHICS``` variable.
  If you use ``s2e image_build``, add the ``-g`` option. This is convenient if you modify existing build scripts
  and want to monitor the installation as it goes.

* Look at the serial output. Most installation steps redirect stdout / stderr to the serial port, which is recorded
  in ``*_serial.txt`` files.

* Check that Virtual Box, VMware, or any other virtualization software is not running. It interferes with KVM.
  This should not be a problem if you use ``s2e image_build``, which checks this before starting the build process.

* If you need to debug an intermediate installation step on Windows, set ```DEBUG_INTERMEDIATE_RULES``` to 1.
  The makefile will checkpoint the disk images after each build step. If you abort the build, it will restart
  the aborted step using a fresh image copy from the previous build step.
