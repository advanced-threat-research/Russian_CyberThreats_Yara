rule fancybear_seduploader_payload_decode_fns : TAU RU APT   
   {   
     meta:   
       author = "CarbonBlack Threat Research" // tharuyama   
       date = "2018-Oct-29"   
       description = "Designed to catch Seduploader"   
       rule_version = 1   
   	yara_version = "3.8.1"   
   	Confidence = "Prod"   
   	Priority = "High"   
       TLP = "White"   
       exemplar_hashes = "c3b2c7bbd2aa1e3100b9382ed78dfa0041af764e0e02013acdf282410b302ead, 1140c624fbfe28b9ef19fef2e9aa251adfbe8c157820d5f0356d88b4d80c2c88, ef027405492bc0719437eb58c3d2774cc87845f30c40040bbebbcc09a4e3dd18"    
       // the followings are own definitions      
       sample_md5 = "AA2CD9D9FC5D196CAA6F8FD5979E3F14"   
      
     strings:   
       // fn_decode_string     
       $0x10002f3f = { 55 8B EC 51 53 8B 5D 0C 56 8D 43 01 50 E8 ?? ?? ?? ?? 8B F0 33 C0 89 45 0C 59 85 DB }   
       $0x10002f5d = { 57 8B 7D 08 2B FE }   
       $0x10002f63 = { 8D 0C 30 C7 45 FC ?? ?? ?? ?? 33 D2 F7 75 FC 8A 82 ?? ?? ?? ?? 32 04 0F 88 01 8B 45 0C 40 89 45 0C 3B C3 }   
       $0x10002f89 = { 8B C6 5E 5B 8B E5 5D C3 }   
       // fn_rolling_xor   
       $0x10002b9e = { 55 8B EC 56 8B 75 08 85 F6 }   
       $0x10002ba9 = { 57 8B 7D 10 85 FF }   
       $0x10002bb1 = { 83 7D 0C ?? 53 8B DE }   
       $0x10002bbc = { 33 D2 8B C6 F7 75 14 8A 0C 3A 30 0B 43 46 3B 75 0C }   
       $0x10002bd4 = { 8B C6 5E 5D C3 }       
     condition:   
       all of them   
   }