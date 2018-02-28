# Events Listing

Below is a list of all the events available in LC along with a sample output. Please note that there may be some variability between platforms.

## Events

### STARTING_UP

```
{
  "notification.STARTING_UP": {
    "base.TIMESTAMP": 1455854079
  }
}
```

### SHUTTING_DOWN

```
{
  "notification.SHUTTING_DOWN": {
    "base.TIMESTAMP": 1455674775
  }
}
```

### NEW_PROCESS

```
{
  "notification.NEW_PROCESS": {
    "base.PARENT": {
      "base.PARENT_PROCESS_ID": 7076, 
      "base.COMMAND_LINE": "\"C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\Common7\\IDE\\devenv.exe\"  ", 
      "base.MEMORY_USAGE": 438730752, 
      "base.PROCESS_ID": 5820, 
      "base.THREADS": 39, 
      "base.FILE_PATH": "C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\Common7\\IDE\\devenv.exe", 
      "base.BASE_ADDRESS": 798949376
    }, 
    "base.PARENT_PROCESS_ID": 5820, 
    "base.COMMAND_LINE": "-q  -s {0257E42D-7F05-42C4-B402-34C1CC2F2EAD} -p 5820", 
    "base.FILE_PATH": "C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\VC\\vcpackages\\VCPkgSrv.exe", 
    "base.PROCESS_ID": 1080, 
    "base.THREADS": 9, 
    "base.MEMORY_USAGE": 8282112, 
    "base.TIMESTAMP": 1456285660, 
    "base.BASE_ADDRESS": 4194304
  }
}
```

### TERMINATE_PROCESS

```
{
  "notification.TERMINATE_PROCESS": {
    "base.PARENT_PROCESS_ID": 5820, 
    "base.TIMESTAMP": 1456285661, 
    "base.PROCESS_ID": 6072
  }
}
```

### DNS_REQUEST

```
{
  "notification.DNS_REQUEST": {
    "base.DNS_TYPE": 1, 
    "base.TIMESTAMP": 1456285240, 
    "base.DNS_FLAGS": 0, 
    "base.DOMAIN_NAME": "time.windows.com"
  }
}
```

### CODE_IDENTITY

```
{
  "notification.CODE_IDENTITY": {
    "base.MEMORY_SIZE": 0, 
    "base.FILE_PATH": "C:\\Users\\dev\\AppData\\Local\\Temp\\B1B207E5-300E-434F-B4FE-A4816E6551BE\\dismhost.exe", 
    "base.TIMESTAMP": 1456285265, 
    "base.SIGNATURE": {
      "base.CERT_ISSUER": "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Code Signing PCA", 
      "base.CERT_CHAIN_STATUS": 124, 
      "base.FILE_PATH": "C:\\Users\\dev\\AppData\\Local\\Temp\\B1B207E5-300E-434F-B4FE-A4816E6551BE\\dismhost.exe", 
      "base.CERT_SUBJECT": "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, OU=MOPR, CN=Microsoft Corporation"
    }, 
    "base.HASH": "4ab4024eb555b2e4c54d378a846a847bd02f66ac54849bbce5a1c8b787f1d26c"
  }
}
```

### NEW_TCP4_CONNECTION

```
{
  "notification.NEW_TCP4_CONNECTION": {
    "base.PROCESS_ID": 6788, 
    "hbs.PARENT_ATOM": "hLiZg7ppJHXI8vE1fzKx4g==", 
    "base.DESTINATION": {
      "base.IP_ADDRESS": "172.16.223.219", 
      "base.PORT": 80
    }, 
    "base.STATE": 5, 
    "hbs.THIS_ATOM": "MQ5Nj6xiNNriA7hgL+Ql4Q==", 
    "base.TIMESTAMP": 1468335512047, 
    "base.SOURCE": {
      "base.IP_ADDRESS": "172.16.223.163", 
      "base.PORT": 63581
    }
  }
}
```

### NEW_UDP4_CONNECTION

```
{
  "notification.NEW_UDP4_CONNECTION": {
    "hbs.THIS_ATOM": "e0Bfg5DShpYmSNIXjSV0Qg==", 
    "base.TIMESTAMP": 1468335452828, 
    "base.PROCESS_ID": 924, 
    "base.IP_ADDRESS": "172.16.223.163", 
    "base.PORT": 63057
  }
}
```

### HIDDEN_MODULE_DETECTED

### MODULE_LOAD

```
{
  "notification.MODULE_LOAD": {
    "base.MEMORY_SIZE": 241664, 
    "base.PROCESS_ID": 2904, 
    "hbs.PARENT_ATOM": "LkdMSTYqHszfBqks/V3G/Q==", 
    "base.FILE_PATH": "C:\\Windows\\System32\\imm32.dll", 
    "base.MODULE_NAME": "imm32.dll", 
    "hbs.THIS_ATOM": "gTjW2Okrg8lUsVMyXcK3Eg==", 
    "base.TIMESTAMP": 1468335264989, 
    "base.BASE_ADDRESS": 140715814092800
  }
}
```

### FILE_CREATE

```
{
  "notification.FILE_CREATE": {
    "hbs.THIS_ATOM": "2he3xMSaMgT7omBnIf69Nw==", 
    "base.FILE_PATH": "C:\\Users\\dev\\AppData\\Local\\Microsoft\\Windows\\WebCache\\V01tmp.log", 
    "base.TIMESTAMP": 1468335271948
  }
}
```

### FILE_DELETE

```
{
  "notification.FILE_DELETE": {
    "hbs.THIS_ATOM": "4000du1FOoXsOXEXsrNEpw==", 
    "base.FILE_PATH": "C:\\Users\\dev\\AppData\\Local\\Temp\\EBA4E4F0-3020-459E-9E34-D5336E244F05\\api-ms-win-core-processthreads-l1-1-2.dll", 
    "base.TIMESTAMP": 1468335611906
  }
}
```

### NETWORK_SUMMARY

```
{
  "notification.NETWORK_SUMMARY": {
    "base.PARENT": {
      "base.PARENT_PROCESS_ID": 876, 
      "base.COMMAND_LINE": "C:\\WINDOWS\\system32\\compattelrunner.exe -maintenance", 
      "base.MEMORY_USAGE": 3858432, 
      "base.PROCESS_ID": 5164, 
      "base.THREADS": 3, 
      "base.FILE_PATH": "C:\\WINDOWS\\system32\\compattelrunner.exe", 
      "base.BASE_ADDRESS": 140699034058752
    }, 
    "base.PARENT_PROCESS_ID": 5164, 
    "base.COMMAND_LINE": "C:\\WINDOWS\\system32\\CompatTelRunner.exe -m:invagent.dll -f:RunUpdateW", 
    "base.MEMORY_USAGE": 6668288, 
    "base.PROCESS_ID": 652, 
    "base.NETWORK_ACTIVITY": [
      {
        "base.DESTINATION": {
          "base.IP_ADDRESS": "65.55.252.190", 
          "base.PORT": 443
        }, 
        "base.TIMESTAMP": 1456285233, 
        "base.STATE": 5, 
        "base.PROCESS_ID": 652, 
        "base.SOURCE": {
          "base.IP_ADDRESS": "172.16.223.156", 
          "base.PORT": 49724
        }
      }, 
      {
        "base.DESTINATION": {
          "base.IP_ADDRESS": "191.239.54.52", 
          "base.PORT": 80
        }, 
        "base.TIMESTAMP": 1456285233, 
        "base.STATE": 5, 
        "base.PROCESS_ID": 652, 
        "base.SOURCE": {
          "base.IP_ADDRESS": "172.16.223.156", 
          "base.PORT": 49727
        }
      }
    ], 
    "base.THREADS": 4, 
    "base.FILE_PATH": "C:\\WINDOWS\\system32\\CompatTelRunner.exe", 
    "base.TIMESTAMP": 1456285231, 
    "base.BASE_ADDRESS": 140699034058752
  }
}
```

### FILE_GET_REP

### FILE_DEL_REP

### FILE_MOV_REP

### FILE_HASH_REP

### FILE_INFO_REP

### DIR_LIST_REP

### MEM_MAP_REP

### MEM_READ_REP

### MEM_HANDLES_REP

### MEM_FIND_HANDLES_REP

### MEM_STRINGS_REP

### MEM_FIND_STRING_REP

### OS_SERVICES_REP

```
{
  "notification.OS_SERVICES_REP": {
    "hbs.THIS_ATOM": "tpYIEAN9AJrD7nG70Eioqw==", 
    "base.SVCS": [
      {
        "base.PROCESS_ID": 0, 
        "base.SVC_TYPE": 32, 
        "base.DLL": "%SystemRoot%\\System32\\AJRouter.dll", 
        "base.SVC_NAME": "AJRouter", 
        "base.SVC_STATE": 1, 
        "base.HASH": "a09ae69c9de2f3765417f212453b6927c317a94801ae68fba6a8e8a7cb16ced7", 
        "base.SVC_DISPLAY_NAME": "AllJoyn Router Service", 
        "base.EXECUTABLE": "%SystemRoot%\\system32\\svchost.exe -k LocalService"
      }, 
      {
        "base.PROCESS_ID": 0, 
        "base.SVC_TYPE": 16, 
        "base.SVC_NAME": "ALG", 
        "base.SVC_STATE": 1, 
        "base.HASH": "f61055d581745023939c741cab3370074d1416bb5a0be0bd47642d5a75669e12", 
        "base.SVC_DISPLAY_NAME": "Application Layer Gateway Service", 
        "base.EXECUTABLE": "%SystemRoot%\\System32\\alg.exe"
      },
.....
```

### OS_DRIVERS_REP

```
{
  "notification.OS_DRIVERS_REP": {
    "base.SVCS": [
      {
        "base.PROCESS_ID": 0, 
        "base.SVC_TYPE": 1, 
        "base.SVC_NAME": "1394ohci", 
        "base.SVC_STATE": 1, 
        "base.HASH": "9ecf6211ccd30273a23247e87c31b3a2acda623133cef6e9b3243463c0609c5f", 
        "base.SVC_DISPLAY_NAME": "1394 OHCI Compliant Host Controller", 
        "base.EXECUTABLE": "\\SystemRoot\\System32\\drivers\\1394ohci.sys"
      }, 
      {
        "base.PROCESS_ID": 0, 
        "base.SVC_TYPE": 1, 
        "base.SVC_NAME": "3ware", 
        "base.SVC_STATE": 1, 
        "base.SVC_DISPLAY_NAME": "3ware", 
        "base.EXECUTABLE": "System32\\drivers\\3ware.sys"
      }, 
.....
```

### OS_KILL_PROCESS_REP

### OS_PROCESSES_REP

### OS_AUTORUNS_REP

```
{
  "notification.OS_AUTORUNS_REP": {
    "base.TIMESTAMP": 1456194620, 
    "base.AUTORUNS": [
      {
        "base.REGISTRY_KEY": "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VMware User Process", 
        "base.FILE_PATH": "\"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\" -n vmusr", 
        "base.HASH": "036608644e3c282efaac49792a2bb2534df95e859e2ddc727cd5d2e764133d14"
      }, 
      {
        "base.REGISTRY_KEY": "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\RoccatTyonW", 
        "base.FILE_PATH": "\"C:\\Program Files (x86)\\ROCCAT\\Tyon Mouse\\TyonMonitorW.EXE\"", 
        "base.HASH": "7d601591625d41aecfb40b4fc770ff6d22094047216c4a3b22903405281e32e1"
      }, 
.....
```

### HISTORY_DUMP_REP

### EXEC_OOB

```
{
  "notification.EXEC_OOB": {
    "base.PARENT_PROCESS_ID": 660, 
    "base.COMMAND_LINE": "\"C:\\Program Files\\WindowsApps\\Microsoft.Messaging_2.13.20000.0_x86__8wekyb3d8bbwe\\SkypeHost.exe\" -ServerName:SkypeHost.ServerServer", 
    "base.MEMORY_USAGE": 8253440, 
    "base.PROCESS_ID": 3904, 
    "base.THREADS": 14, 
    "base.FILE_PATH": "C:\\Program Files\\WindowsApps\\Microsoft.Messaging_2.13.20000.0_x86__8wekyb3d8bbwe\\SkypeHost.exe", 
    "base.STACK_TRACES": [
      {
        "base.STACK_TRACE_FRAMES": [
          {
            "base.STACK_TRACE_FRAME_SP": 10483804, 
            "base.STACK_TRACE_FRAME_PC": 1718227232, 
            "base.STACK_TRACE_FRAME_FP": 10483796
          }, 
          {
            "base.STACK_TRACE_FRAME_SP": 10483812, 
            "base.STACK_TRACE_FRAME_PC": 45029040433702885, 
            "base.STACK_TRACE_FRAME_FP": 10483804
          }, 
          {
            "base.STACK_TRACE_FRAME_SP": 10483820, 
            "base.STACK_TRACE_FRAME_PC": 4035225266123964416, 
            "base.STACK_TRACE_FRAME_FP": 10483812
          }
        ], 
        "base.THREAD_ID": 4708
      }
    ], 
    "base.TIMESTAMP": 1456254033, 
    "base.BASE_ADDRESS": 18415616
  }
}
```

### MODULE_MEM_DISK_MISMATCH

### YARA_DETECTION

### SERVICE_CHANGE

```
{
  "notification.SERVICE_CHANGE": {
    "base.PROCESS_ID": 0, 
    "base.SVC_TYPE": 32, 
    "base.DLL": "%SystemRoot%\\system32\\wlidsvc.dll", 
    "base.SVC_NAME": "wlidsvc", 
    "base.SVC_STATE": 1, 
    "base.HASH": "b37199495115ed423ba99b7317377ce865bb482d4e847861e871480ac49d4a84", 
    "base.SVC_DISPLAY_NAME": "Microsoft Account Sign-in Assistant", 
    "hbs.THIS_ATOM": "JNJNyxnDjYgPWYYU0Q+U4Q==", 
    "base.TIMESTAMP": 1467942600540, 
    "base.EXECUTABLE": "%SystemRoot%\\system32\\svchost.exe -k netsvcs"
  }
}
```

### DRIVER_CHANGE

### AUTORUN_CHANGE

### FILE_MODIFIED

```
{
  "notification.FILE_MODIFIED": {
    "hbs.THIS_ATOM": "3mdgAXtjs1Z6JRcb8NCIlg==", 
    "base.FILE_PATH": "C:\\Users\\dev\\AppData\\Local\\Microsoft\\Windows\\WebCache\\V01.log", 
    "base.TIMESTAMP": 1468335272949
  }
}
```

### NEW_DOCUMENT

```
{
  "notification.NEW_DOCUMENT": {
    "hbs.PARENT_ATOM": "BNzkR7w4+NFfwItSXu69yA==", 
    "hbs.THIS_ATOM": "BNzkR7w4+NFfwItSXu69yA==", 
    "base.FILE_PATH": "C:\\Users\\dev\\Desktop\\New Text Document.txt", 
    "base.TIMESTAMP": 1468335816308, 
    "base.HASH": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

### GET_DOCUMENT_REP

### USER_OBSERVED
```
{
  "notification.USER_OBSERVED": {
    "hbs.PARENT_ATOM": "e7c2dcfb-1da4-88ad-a20c-6447a31bbeca", 
    "hbs.THIS_ATOM": "d9db23be-c938-7140-70fe-d74c6c9ce7d8", 
    "base.TIMESTAMP": 1479241363009, 
    "base.USER_NAME": "root"
  }
}
```