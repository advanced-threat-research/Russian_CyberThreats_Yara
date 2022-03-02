rule fancybear_zebrocy_downloader1_go {   
     meta:   
       author = "CarbonBlack Threat Research" // tharuyama   
       date = "2019-Mar-15"   
       description = "Designed to catch Zebrocy Downloader Type 1 Go"   
       rule_version = 1   
   	yara_version = "3.8.1"   
   	Confidence = "Prod"   
   	Priority = "High"   
       TLP = "White"   
       exemplar_hashes = "fcf03bf5ef4babce577dd13483391344e957fd2c855624c9f0573880b8cba62e"   
     strings:   
       // fn_main_decode_string   
       $0x5c8670 = { 64 8B 0D ?? ?? ?? ?? 8B 89 ?? ?? ?? ?? 3B 61 }   
       $0x5c8682 = { 83 EC ?? 8B 44 24 ?? 89 04 24 8B 44 24 ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 8B 54 24 ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? 89 4C 24 ?? 89 54 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 8B 4C 24 ?? 89 44 24 ?? 89 4C 24 ?? 83 C4 ?? C3 }   
       // hex string   
       $hex_wmi = "776D6963206C6F676963616C6469736B206765742063617074696F6E2C6465736372697074696F6E2C6472697665747970652C70726F76696465726E616D652C73697A65" // wmic logicaldisk get caption,description,drivetype,providername,size   
       $hex_sysinfo = "73797374656D696E666F" // systeminfo   
       $hex_tasklst = "7461736B6C697374" // tasklist   
     condition:   
       all of ($0x5c8*) and 2 of ($hex*)   
   }