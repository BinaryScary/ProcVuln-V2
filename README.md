# ProcVuln-V2
C# rewrite of ProcVuln, supports JSON entries and does not cache file before parsing (supports huge files)

ProcVuln parses sysinternals Procmon (XML) output to find filesystem vulnerabilities using user created JSON files.

### Custom Entry Properties:
"Privileged" : "True" # Process has integrity High or System  
"PathWritable" : "True" # Path is writable by current user  
"Context" : "" # used so entries can reference others  
"Equals" : "Path" # a context property, if current entry and context entry share the same property this will be True  
"$Name" : {...} # Context entry, will not be shown in findings and can be used as Context property  

### Example JSON indicators file
finding DLL hijacks:
```
{
   "$badPath":{
      "Operation":"CreateFile",
      "Result":"NAME NOT FOUND",
      "Privileged":"True",
      "PathWritable":"True"
   },
   "dllhijack":{
      "Operation":"Load Image",
      "Context":{
         "entry":"$badPath",
         "equal":"Path"
      }
   }
}
```
### Results
```
dllhijack:
ProcessIndex=776;Time_of_Day=6:30:45.1776068 AM;Process_Name=***;PID=4756;Operation=Load Image;Path=***;Result=SUCCESS;Detail=Image Base: 0x7ffe93760000, Image Size: 0x285000

dllhijack:
ProcessIndex=776;Time_of_Day=6:30:45.1804342 AM;Process_Name=***;PID=4756;Operation=Load Image;Path=***;Result=SUCCESS;Detail=Image Base: 0x7ffe92a10000, Image Size: 0x7000

dllhijack:
ProcessIndex=776;Time_of_Day=6:30:45.3085485 AM;Process_Name=***;PID=4756;Operation=Load Image;Path=***;Result=SUCCESS;Detail=Image Base: 0x52270000, Image Size: 0x398000

...
```
