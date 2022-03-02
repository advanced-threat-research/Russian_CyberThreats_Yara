rule fancybear_zebrocy_downloader1_delphi_v3 : TAU RU APT   
   {   
     meta:   
       author = "CarbonBlack Threat Research" // tharuyama   
       date = "2019-Mar-11"   
       description = "Designed to catch Zebrocy Downloader Type 1 Delphi (variant 3)"   
       rule_version = 1   
   	yara_version = "3.8.1"   
   	Confidence = "Prod"   
   	Priority = "High"   
       TLP = "White"   
       exemplar_hashes = "03ff895c99555f00792a41e3b014f16ef6b4bb0c74d1fa2237a6a9275e2b2109, 001cf7af29382f4f784fe45df131ca9e14908c6c0717899780f9354b8a5f0090"   
     strings:   
       // fn_decode_string   
       $0x4a1dcc = { 55 8B EC 6A ?? 6A ?? 6A ?? 6A ?? 53 56 57 8B F9 89 55 ?? 8B 45 ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8B C7 E8 ?? ?? ?? ?? 8B 45 ?? 85 C0 }   
       $0x4a1e03 = { 83 E8 ?? 8B 00 }   
       $0x4a1e08 = { 8B F0 85 F6 }   
       $0x4a1e1c = { 48 83 C8 ?? 40 }   
       $0x4a1e24 = { 8D 45 ?? 50 B9 ?? ?? ?? ?? 8B D3 8B 45 ?? E8 ?? ?? ?? ?? 8B 4D ?? 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? E8 ?? ?? ?? ?? 8B D0 8D 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B C7 E8 }   
       $0x4a1e67 = { 33 C0 5A 59 59 64 89 10 68 }   
       $0x4a1e74 = { 8D 45 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? C3 }   
       $0x4a1e89 = { 5F 5E 5B 8B E5 5D C3 }       
       // hex string   
       $hex_word = "4D6963726F736F667420576F7264" // Microsoft Word   
       $hex_repair = "636F756C64206E6F742062652072657061697265642E" // could not be repaired.   
       $hex_entpass = "456E7465722070617373776F726420746F206F70656E2066696C65" // Enter password to open file   
     condition:   
       all of ($0x4a1*) and any of ($hex*)   
   }