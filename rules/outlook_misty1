rule outlook_misty1 {   
       meta:   
           author      = "ESET Research"   
           date        = "22-08-2018"   
           description = "Detects the Turla MISTY1 implementation"                
           reference   = "https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf"   
           source = "https://github.com/eset/malware-ioc/"   
           contact = "github@eset.com"   
           license = "BSD 2-Clause"     
       strings:   
           //and     edi, 1FFh   
           $o1 = {81 E7 FF 01 00 00}   
           //shl     ecx, 9   
           $s1 = {C1 E1 09}   
           //xor     ax, si   
           $s2 = {66 33 C6}   
           //shr     eax, 7   
           $s3 = {C1 E8 07}   
           $o2 = {8B 11 8D 04 1F 50 03 D3 8D 4D C4}   
       condition:   
           $o2 and for all i in (1..#o1):   
               (for all of ($s*) : ($ in (@o1[i] -500 ..@o1[i] + 500)))   
   }