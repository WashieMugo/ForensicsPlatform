# Portable Forensics Platform:
# ============================

## Tools:

	1. FTK Imager:
		a. Purpose :
			- Automate disk image creation and analysis
			- It can create forensic images of hard drives and analyze them.
			- 
		b.  environment:
			- Setup : https://www.exterro.com/digital-forensics-software/ftk-imager
			- 	
	2. Volatility Framework:
		a. Purpose. 
			- Open-source python drive memory forensics Tools.
			- Automates memory analysis by integrating Volatility for extracting digital artifacts from volatile memory (RAM)
			- can list processess, networks, dump files, user activities... etc
	
		b. environment:
			- Microsoft C++ Build Tools (will help buiold python modules so we can run volatility): https://visualstudio.microsoft.com/visual-cpp-build-tools/
			- Python 3 (main language for scripting) : https://www.python.org/downloads/
			- Git for Windows : https://github.com/git-for-windows/git/releases/download/v2.46.0.windows.1/Git-2.46.0-64-bit.exe
			- Volatility Foundation : https://github.com/volatilityfoundation/volatility3.git
			- python-snappy : 
				a. Specific version (in case of known issues)
					pip install c:\Users\...\python_snappy-...-win_amd64.wh1
				b. pip install python-snappy
				c. pip install python-snappy==0.6.0
			- Sample Image File : https://archive.org/download/Africa-DFIRCTF-2021-WK02/20210430-Win10Home-20H2-64bit-memdump.mem.7z
			
				
		c. Installation : ( cd to Volatility Folder) 
			a. Install depedencies: 
				- pip install -r requirements.txt
			b. check if everything is installed correctly:
				- python vol.py -v
			c. Analyse a Memory File:
				- python vol.py -f [path_to_file\examplefile.mem] windows.info
				// we specify the file to analyse and the plugin we are using
				- python vol.py -f [path_to_file\examplefile.mem] windows.info > examplefile.mem.info.txt 
				// here we saved the output of the response
	

	
	3. Autopsy
		a. Purpose:
			- Performs analysis from acopy of a 'suspects' drive.
			
		
		b. environment:
			-  Download : https://www.autopsy.com/download/
				Win : https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0-64bit.msi
				
		c. Access Sample Files:
			-Forensics Image Test Image:  https://cfreds.nist.gov/all/DFIR_AB/ForensicsImageTestimage
		
## Automation areas: 

### FTK Imager
	- 
	- 
	- 
	-
	- ...

### Volatility Framework:
	
	- Get RAM image information
	- Get Process Lists
	- Filter Volatility output with PowerShell Select-String
	- Find process handles with windows.handles
	- Dump Specific files from RAM with Windows.dumpfile
	- Dump all files related to a PID
	- Check executable run options with windows.cmdline
	- Find active network connections with windows.netstat
	- Find local user password hash with windows.hashdump
	- Analyze user actions with windows.registry.userassist
	- Analyze a specific Registry key from RAM with windows.registry.printkey
	- ...
	
### Autopsy:
	- add image as  data source
	
	
# Workflows: 

## Autopsy:
	- add New case :
		*Case Information*
		- case_name:
		- Base_Directory:
		- Type : (Single-User / Multi-User)
		*Optional Information*
		- Case_Number :
		- Examiner :
			- name :
			- Phone: 
			- Email: 
			- Notes: 
	- Add Data Source: (image, local hdd, ...)
		- Select drive
		- Select Ingest modules
		- 