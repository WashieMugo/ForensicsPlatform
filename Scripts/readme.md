# Tools:

## 1. Volatility Framework

  > pip3 install pycryptodome
  > pip3 install yara-python
  > pip3 install pycrypto
  > pip3 install pefile
  > pip3 install capstone 


  -  fix user info automation :  shift from develop to stable branch on vol > 
    - git pull origin stable
    - git checkout stable
    - pip install -r requirements.txt



- ### suported files:
  - Raw Memory dumps (.raw, .dd, .bin, mem)
  - Micreosoft Crash Dump Files (.dmp, .mdmp)
  - Windows Hybernation Files (hiberfil.sys)
  - Virtual machine Memory Files (.vmem, .vmsn, .vmpm, .vmss)
  - HPAK Format (.hpak)
  - Lime Format (.lime)
  - Mach-O Format (.mach-o)

## 2. Autopsy
 Since Automating Autopsy launches the GUI on the COmputer and we'll be using a web interface to automate the process, we'll need to use a headless version of Autopsy(sort of), bu using the CLI library used by Autopsy called TSK(The Sleuth Kit) framework.

  - cmdline-tools:  
    https://www.sleuthkit.org/sleuthkit/download.php


  - dd image:
    https://drive.google.com/drive/folders/1pD_VcStDT-uRhfRQrhpPaTqyuQIxMDJ3
    
    https://cfreds-archive.nist.gov/FileCarving/index.html
  
  

- #### Supported Filess (Images)

  - E01 (EnCase Evidence File)
  - DD (Raw Disk Image)
  - ISO (CD/DVD Image)
  - AFF (Advanced Forensic Format)
  - AD1 (AccessData Custom Content Image)
  - VHD/VHDX (Virtual Hard Disk)

  Outputs:
  General report(html)
  data source summary reports (.xlsx)
  Files (txt) [comma/tab delimited] X

## 3. FTK Imager
