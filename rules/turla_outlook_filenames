rule turla_outlook_filenames {   
       meta:   
           author      = "ESET Research"   
           date        = "22-08-2018"   
           description = "Turla Outlook filenames"   
           reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"   
           source = "https://github.com/eset/malware-ioc/"   
           contact = "github@eset.com"   
           license = "BSD 2-Clause"      
       strings:   
           $s1 = "mapid.tlb"   
           $s2 = "msmime.dll"   
           $s3 = "scawrdot.db"   
       condition:   
           any of them   
   }