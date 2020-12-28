# Espressif-NVS-Analyzer
Dump an NVS partition binary in human readable form

I developed this tool to quickly view changes to the NVS store without having to reload a separate app or requiring any instrumentation in the app under development.  This tool works best as part of a script to read out a binary copy of the NVS partition before analyzing.

The Windows batch script I use is:<br>
```
IF EXIST "nvs_readout.bin" del nvs_readout.bin
esptool.py read_flash 0x9000 0x6000 nvs_readout.bin
analyze_nvs.py nvs_readout.bin -s -b 32
```

Note that this is specific to the flash configuration of the project.  If you unsure of the start address and size to use for the `esptool.py read_flash` command, you can read out the partition table and run Espressif's partition analyzer on it.
```
esptool.py read_flash 0x8000 0x1000 part_table.bin
gen_esp32part.py part_table.bin
```

You should get output like the following:
```
Parsing binary partition input...
Verifying table...
# ESP-IDF Partition Table
# Name, Type, SubType, Offset, Size, Flags
nvs,data,nvs,0x9000,24K,
phy_init,data,phy,0xf000,4K,
factory,app,factory,0x10000,1M,
storage,data,spiffs,0x110000,960K,
```

Here we see that the NVS partition starts at address 0x9000 and is 24K, or 0x6000 bytes long.  You may want to verify this separately for each project, especially if you are switching toolchains (Eclipse, PlatformIO) or frameworks (ESP-IDF, Arduino).  They don't always have the same NVS partition size.

Here is sample output of the script:
```
D:\Users\AFont\Documents\Projects>analyze_nvs.py nvs_readout.bin -s -b 32
Namespace misc
  log             : BLOB  03 00 01 00
Namespace nvs.net80211
  opmode          : U8    2
  sta.ssid        : BLOB
  sta.authmode    : U8    1
  sta.pswd        : BLOB
  sta.pmk         : BLOB  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
  sta.chan        : U8    0
  auto.conn       : U8    1
  bssid.set       : U8    0
  sta.bssid       : BLOB  FF FF FF FF FF FF
  sta.lis_intval  : U16   3
  sta.phym        : U8    3
  sta.phybw       : U8    2
  sta.apsw        : BLOB  FF FF
  sta.apinfo      : BLOB  FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF ...
  sta.scan_method : U8    0
  sta.sort_method : U8    0
  sta.minrssi     : I8    -127
  sta.minauth     : U8    0
  sta.pmf_e       : U8    0
  sta.pmf_r       : U8    0
  ap.chan         : U8    1
  ap.hidden       : U8    0
  ap.max.conn     : U8    4
  bcn.interval    : U16   100
  ap.phym         : U8    3
  ap.phybw        : U8    2
  ap.sndchan      : U8    1
  ap.pmf_e        : U8    0
  ap.pmf_r        : U8    0
  lorate          : U8    0
  country         : BLOB  FF FF FF FF FF FF FF FF FF FF FF FF
  sta.mac         : BLOB  AC 67 B2 2A F5 E4
  ap.mac          : BLOB  AC 67 B2 2A F5 E5
  ap.authmode     : U8    4
  ap.ssid         : BLOB  esp32ap
  ap.passwd       : BLOB  12345678
  ap.pmk          : BLOB  BC DE 5F 13 8F ED B2 AA 00 D0 2E D3 A9 B7 2F 5E B4 62 39 4F C2 70 C3 8D C8 16 4C 3A E2 65 F5 77
Namespace phy
  cal_data        : BLOB  94 11 00 00 AC 67 B2 2A F5 E4 00 00 62 88 00 00 00 00 30 00 48 4B 00 00 62 88 00 00 88 08 30 00 ...
  cal_mac         : BLOB  AC 67 B2 2A F5 E4
  cal_version     : U32   4500
  ```
 
Fields are organized by NVS namespace. 

Blobs will print their full length unless limited by the `-b` blob-limit option, which takes the maximum number of bytes to display.  An ellipsis `...` will be printed if the blob is larger than the limit.

The script has the ability to perform special interpretation on some blobs and print them in a more human friendly format.  Use the `-s` special handling option to turn this feature on.  Right now, only SSID and password fields are identified for special handling.  They will be printed as strings rather than hex data.

Note that SSID blobs contain a 4-byte length field before the string whereas passphrase blobs contain the string directly.  You can verify this by turning off the `-s` switch.
```
D:\Users\AFont\Documents\Projects\softAP>analyze_nvs.py nvs_readout.bin -s
Namespace nvs.net80211
  ...
  ap.ssid         : BLOB  esp32ap
  ap.passwd       : BLOB  12345678
  ...
  
  D:\Users\AFont\Documents\Projects\softAP>analyze_nvs.py nvs_readout.bin
Namespace nvs.net80211
  ...
  ap.ssid         : BLOB  07 00 00 00 65 73 70 33 32 61 70 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  ap.passwd       : BLOB  31 32 33 34 35 36 37 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
  ...
```

# Further Reading

[Espressif NVS API reference](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/storage/nvs_flash.html)
