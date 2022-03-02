rule turla_outlook_gen {   
       meta:   
           author      = "ESET Research"   
           date        = "22-08-2018"   
           description = "Turla Outlook malware"   
           reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"   
           source = "https://github.com/eset/malware-ioc/"   
           contact = "github@eset.com"   
           license = "BSD 2-Clause"       
       strings:   
           $s1 = "Outlook" ascii wide   
           $s2 = "Outlook Express" ascii wide   
           $s3 = "Outlook watchdog" ascii wide   
           $s4 = "Software\\RIT\\The Bat!" ascii wide   
           $s5 = "Mail Event Window" ascii wide   
           $s6 = "Software\\Mozilla\\Mozilla Thunderbird\\Profiles" ascii wide   
           $s7 = "%%PDF-1.4\n%%%c%c\n" ascii wide   
           $s8 = "%Y-%m-%dT%H:%M:%S+0000" ascii wide   
           $s9 = "rctrl_renwnd32" ascii wide   
           $s10 = "NetUIHWND" ascii wide   
           $s11 = "homePostalAddress" ascii wide   
           $s12 = "/EXPORT;OVERRIDE;START=-%d;END=-%d;FOLDER=%s;OUT=" ascii wide   
           $s13 = "Re:|FWD:|AW:|FYI:|NT|QUE:" ascii wide   
           $s14 = "IPM.Note" ascii wide   
           $s15 = "MAPILogonEx" ascii wide   
           $s16 = "pipe\\The Bat! %d CmdLine" ascii wide   
           $s17 = "PowerShellRunner.dll" ascii wide   
           $s18 = "cmd container" ascii wide   
           $s19 = "mapid.tlb" ascii wide nocase   
           $s20 = "Content-Type: F)*+" ascii wide fullword   
       condition:   
           5 of them   
   }