
******************************************************************************

  Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub.

    By Oleksiuk Dmytro (aka Cr4sh)
    http://twitter.com/d_olex
    http://blog.cr4.sh
    mailto:cr4sh0@gmail.com

******************************************************************************

Features:

  - Enumerating loaded kernel modules and segments creation for them.
  - Loading debug symbols for kernel modules.

Based on original vmware_modules.py from Hex Blog article (http://www.hexblog.com/?p=94).

Changes:
   
  * Changed nt!PsLoadedModuleList finding algo, 'cause using FS segment base
    for this -- is bad idea (FS not always points to the _KPCR).
    
  * Added complete support of Windows x64.
  
  * Fixed bugs in .PDB loading for mdules with the 'non-canonical' image path.

Tested on IDA 6.1 with IDAPython v1.5.2 on Windows XP, Vista, 7 (x32 and x64)
as debug targets.
