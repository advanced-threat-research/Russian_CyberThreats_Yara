rule fancybear_zebrocy_downloader2_cpp_fn_bs_decode : TAU RU APT   
   {   
     meta:   
       author = "CarbonBlack Threat Research" // tharuyama   
       date = "2019-Mar-11"   
       description = "Designed to catch Zebrocy Downloader Type 2 C++"   
       rule_version = 1   
   	yara_version = "3.8.1"   
   	Confidence = "Prod"   
   	Priority = "High"   
       TLP = "White"   
       exemplar_hashes = "489a1b13b5ec415f24bc4f1b4ed6c6e0bdc50ae95513645a839655bc75d4d9d6, 6f2589be92c2d0fa6050e52fbedb967c2590a8abbc4a9459fb7f78bc52407195"   
       // own definitions   
       sample_md5 = "CC6E8B89C8FD3DA84CFD747FB7BFEA79"   
       function_address = "0x402410"   
       function_name = "fn_bs_decode"   
     strings:   
       $0x402410 = { 55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 83 EC ?? A1 ?? ?? ?? ?? 33 C5 89 45 ?? 53 56 50 8D 45 ?? 64 A3 ?? ?? ?? ?? 33 DB 89 7D ?? 89 5D ?? 6A ?? C7 45 ?? ?? ?? ?? ?? 53 8D 45 ?? 50 8D 4D ?? C7 45 ?? ?? ?? ?? ?? 89 5D ?? 88 5D ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 75 ?? 8B C6 83 FA }   
       $0x402475 = { 8B 4D ?? 03 C8 8B C6 83 FA }   
       $0x40248d = { 8A 10 8A 19 88 18 40 88 11 3B C1 }   
       $0x40249c = { C7 45 ?? ?? ?? ?? ?? 89 5D ?? C6 45 ?? ?? C6 45 ?? ?? 89 5D ?? 39 5D }   
       $0x4024b6 = { 83 7D ?? ?? 8B 45 }       
       $0x4024e0 = { 33 DB 6A ?? 53 8D 45 ?? BE ?? ?? ?? ?? 50 8D 4D ?? 89 75 ?? 89 5D ?? 88 5D ?? E8 ?? ?? ?? ?? C6 45 ?? ?? 89 77 ?? 89 5F ?? 88 1F 8B 45 ?? 8B 4F ?? 40 ?? ?? C7 45 ?? ?? ?? ?? ?? 3B C1 }   
       $0x40251f = { 83 CE ?? 3B C8 }   
       $0x402530 = { 8B D1 2B D0 83 FA }   
       $0x402539 = { 8B F2 3B F3 }   
       $0x40253f = { 8B 57 ?? 83 FA }   
       $0x402558 = { 2B CE 2B C8 51 03 DE 03 D8 03 D0 53 52 E8 ?? ?? ?? ?? 8B 47 ?? 2B C6 83 C4 ?? 83 7F ?? ?? 89 47 }   
       $0x40257b = { 8B 0F C6 04 01 }   
       $0x402583 = { 8B CF C6 04 01 }   
       $0x40258b = { 53 8B D8 2B D9 8B F7 E8 }   
       $0x402597 = { 33 D2 33 F6 39 57 }   
       $0x4025a4 = { 8B 5D ?? 8B 45 ?? 8B C8 83 FB }   
       $0x4025c2 = { 0F BE 04 10 83 C0 }   
       $0x4025d3 = { 0F BE 04 10 }   
       $0x4025e3 = { C0 E0 ?? 88 04 31 8B 45 ?? 8B 5D ?? 8B CB 83 F8 }   
       $0x402600 = { 83 F8 ?? 8B C3 }   
       $0x40260a = { 0F BE 44 10 ?? 83 C0 }   
       $0x402614 = { 83 F8 ?? 8B C3 }   
       $0x40261e = { 0F BE 44 10 }   
       $0x40262f = { 24 ?? 08 04 31 46 83 C2 ?? 3B 77 }   
       $0x40264b = { 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 }       
       $0x40266b = { 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 }   
       $0x40267c = { 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 }       
       $0x4026a6 = { 8B C7 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 }   
       $0x41f770 = { 8B 45 ?? 83 E0 }   
       $0x41f77c = { 83 65 ?? ?? 8B 4D }   
       $0x41f789 = { 8B 54 24 ?? 8D 42 ?? 8B 4A ?? 33 C8 E8 ?? ?? ?? ?? 8B 4A ?? 33 C8 E8 ?? ?? ?? ?? B8 }   
     condition:   
       all of them   
   }