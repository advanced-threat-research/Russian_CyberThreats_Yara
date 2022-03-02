rule fancybear_zebrocy_downloader1_delphi_v2 : TAU RU APT   
   {   
     meta:   
       author = "CarbonBlack Threat Research" // tharuyama   
       date = "2019-Mar-11"   
       description = "Designed to catch Zebrocy Downloader Type 1 Delphi (variant 2)"   
       rule_version = 1   
   	yara_version = "3.8.1"   
   	Confidence = "Prod"   
   	Priority = "High"   
       TLP = "White"   
       exemplar_hashes = "65de07fc6b821d9fd3497cfa64212df2d39935dd515a86eda80d08086b183a3f, cd925e2464d251f02b4d425e301acf276e13eeccbbf5996ade5a6f355802abb7"   
     strings:   
       // fn_decode_string   
       $0x493840 = { 55 8B EC 33 C9 51 51 51 51 53 56 57 8B FA 89 45 ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C7 E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 }   
       $0x493875 = { 83 E8 ?? 8B 00 }   
       $0x49387a = { 8B F0 85 F6 }   
       $0x49388e = { 48 83 C8 ?? 40 }   
       $0x493896 = { 8D 45 ?? 50 B9 ?? ?? ?? ?? 8B D3 8B 45 ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 8D 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B C7 E8 }   
       $0x4938d9 = { 33 C0 5A 59 59 64 89 10 68 }   
       $0x4938e6 = { 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 }   
       $0x4938fb = { 5F 5E 5B 8B E5 5D C3 }   
       // hex string   
       $hex_word = "4D6963726F736F667420576F7264" // Microsoft Word   
       $hex_cmd = "636D642E657865202F6320" // cmd.exe /c   
       $hex_sysinfo = "53595354454D494E464F" // SYSTEMINFO   
       $hex_tasklst = "5441534B4C495354" // TASKLIST   
       $hex_total = "2C20546F74616C2073697A653A20" // , Total size:   
     condition:   
       all of ($0x4938*) and any of ($hex*)   
   }