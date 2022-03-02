import "pe"
rule turla_outlook_exports {   
       meta:   
           author      = "ESET Research"   
           date        = "22-08-2018"   
           description = "Export names of Turla Outlook Malware"   
           reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"   
           source = "https://github.com/eset/malware-ioc/"   
           contact = "github@eset.com"   
           license = "BSD 2-Clause"     
       condition:   
           (pe.exports("install") or pe.exports("Install")) and   
           pe.exports("TBP_Initialize") and   
           pe.exports("TBP_Finalize") and   
           pe.exports("TBP_GetName") and   
           pe.exports("DllRegisterServer") and   
           pe.exports("DllGetClassObject")   
   }