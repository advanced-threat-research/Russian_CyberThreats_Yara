rule fancybear_zebrocy_downloader1_delphi_v1 : TAU RU APT   
   {   
     meta:   
       author = "CarbonBlack Threat Research" // tharuyama   
       date = "2019-Mar-11"   
       description = "Designed to catch Zebrocy Downloader Type 1 Delphi (variant 1)"   
       rule_version = 1   
   	yara_version = "3.8.1"   
   	Confidence = "Prod"   
   	Priority = "High"   
       TLP = "White"   
       exemplar_hashes = "6ad3eb8b5622145a70bec67b3d14868a1c13864864afd651fe70689c95b1399a, 87f363afc9778efc78dd3e0ced112d8d66a09a8924091f0927ed02a7b64850d2"   
     strings:     
       // fn_decode_string   
       $0x6846c8 = { 55 8B EC 83 C4 ?? 33 C9 89 4D ?? 89 4D ?? 89 4D ?? 89 55 ?? 89 45 ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 ?? 89 45 ?? 83 7D }   
       $0x684709 = { 8B 45 ?? 83 E8 ?? 8B 00 89 45 }   
       $0x684714 = { 8B 45 ?? 85 C0 }   
       $0x68471b = { 89 45 ?? C7 45 }   
       $0x68472f = { 48 83 C8 ?? 40 }   
       $0x684737 = { 8D 45 ?? 50 B9 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 [0-1] 8D 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B 45 }       
       $0x684784 = { 33 C0 5A 59 59 64 89 10 68 }   
       $0x684791 = { 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 ?? E8 ?? ?? ?? ?? C3 }   
       $0x6847ae = { 8B E5 5D C3 }   
       // hex string   
       $hex_cmd = "636D642E657865202F6320" // cmd.exe /c   
       $hex_sysinfo = "53595354454D494E464F" // SYSTEMINFO   
       $hex_tasklst = "5441534B4C495354" // TASKLIST   
       $hex_winword = "77696E776F72642E657865" // winword.exe   
     condition:   
       all of ($0x684*) and any of ($hex*)   
   }