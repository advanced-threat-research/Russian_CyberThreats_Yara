rule exatrack_turla   
   {   
    strings:   
    $strings_crypt = { 4d 8b c1 41 ba 40 00 00 00 41 ?? ?? ?? 41 ?? ?? 49 83 c0 01 49 83   
   ea 01 75 ??}   
    $hash_part1 = { 49 c1 c3 0e 4e ?? ?? ?? 4c 33 dd 4c 03 c7 4c 03 c1 48 c1 c0 10 49 33   
   c0 4d 03 c3 48 03 e8 48 c1 c8 0c 48 33 c5 49 c1 cb 07 4d 33 d8 4c 03 c0 49 03 eb 49 c1 c3   
   17 4c 33 dd 48 c1 c8 18 49 33 c0 4d 03 c3 48 03 e8 49 c1 cb 1b 4d 33 d8 4c 03 df 4c 03 d9   
   48 c1 c0 05 48 33 c5 4a ?? ?? ?? ??}   
    condition:   
    1 of them   
   }