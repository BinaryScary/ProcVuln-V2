# ProcVuln-V2
C# rewrite of ProcVuln, supports JSON entries and does not cache file before parsing (supports huge files)

ProcVuln parses sysinternals Procmon (XML) output to find filesystem vulnerabilities using user created JSON files.

Usage: `ProcVuln-V2.exe Procmon.xml Indicators.json [domain/user]`

### Custom Entry Properties:
"Privileged" : "True" # Process has integrity High or System  
"PathWritable" : "True" # Path is writable by current user  
"Context" : "" # used so entries can reference others  
"Equals" : "Path" # a context property, if current entry and context entry share the same property this will be True  
"$Name" : {...} # Context entry, will not be shown in findings and can be used as Context property  

### Example JSON indicators file
finding DLL hijack vulnerabilities:
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
        ProcessIndex=390
        Time_of_Day=6:28:00.5791200 AM
        Process_Name=***
        PID=3396
        Operation=ReadFile
        Path=***
        Result=SUCCESS
        Detail=Offset: 143,360, Length: 32,768, I/O Flags: Non-cached, Paging I/O, Synchronous Paging I/O, Priority: Normal

dllhijack:
        ProcessIndex=390
        Time_of_Day=6:28:00.5813608 AM
        Process_Name=***
        PID=3396
        Operation=ReadFile
        Path=***
        Result=SUCCESS
        Detail=Offset: 49,152, Length: 32,768, I/O Flags: Non-cached, Paging I/O, Synchronous Paging I/O, Priority: Normal

...
```
