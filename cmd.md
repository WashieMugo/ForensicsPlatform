img_stat [IMAGE_PATH]
fls -r -m / [IMAGE_PATH]

blkcat -o [offset] [IMAGE_PATH] 0

Ascii Display :	
	blkcat -a -o 65664 "E:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\Files\\images\\2020JimmyWilson.E01" 0



Inode Listing: (last 20  linked, allocated and used inodes )
	ils  -o  [offset] -m -l [IMAGE_PATH]
	
Recursive File and Directory Listing with Path Information: 
	fls -r -p -o [offset] [IMAGE_PATH]
	
Directories: 
	fls -r -o [offset] [IMAGE_PATH]" | findstr /R "^d"

Executables & Compressed files:
	fls -r -o [offset] [IMAGE_PATH] | findstr /I "\.exe \.zip \.rar "

Mail & Communications :
	fls -r -o [offset] [IMAGE_PATH] | findstr /I "\.pst \.ost \.eml \.msg"
	
Documents:
	fls -r -o [offset] [IMAGE_PATH] | findstr /I "\.xlsx \.pptx \.docx \.pdf"
Compressed Files: 
	 fls -r -o [offset] [IMAGE_PATH] | findstr /I "\.tar \.7z \.rar \.zip"
Databases:	
	fls -r -o [offset] [IMAGE_PATH] | findstr /I "\.db \.sqlite \.txt \.pdf  \.log \.conf \.ini SYSTEM SOFTWARE SECURITY SAM NTUSER.DAT"

fls -r -o 65664 "E:\Work\Abdulrhman\Forensics Platform\Scripts\Files\images\2020JimmyWilson.E01" | findstr /I "\.db \.sqlite"

	
Best info: 


File System Statistics: 
	fsstat -o  [offset] [IMAGE_PATH] 
file directory listing : 
	fls -o [offset] [IMAGE_PATH] 
	
last 20  linked, allocated and used inodes
	ils -o [offset] -l -a -Z -m [IMAGE_PATH] 
	