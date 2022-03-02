rule turla_outlook_log {   
       meta:   
           author      = "ESET Research"   
           date        = "22-08-2018"   
           description = "First bytes of the encrypted Turla Outlook logs"   
           reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"   
           source = "https://github.com/eset/malware-ioc/"   
           contact = "github@eset.com"   
           license = "BSD 2-Clause"      
       strings:   
           //Log begin: [...] TVer   
           $s1 = {01 87 C9 75 C8 69 98 AC E0 C9 7B [21] EB BB 60 BB 5A}   
       condition:   
           $s1 at 0   
   }