# ida_xtensa
Loader and CPU support for ida 6.8

1. Move esp8266_loader.py to $IDA_DIR/loaders, xtensa.py to $IDA_DIR/procs
2. Select resersing file 
3. Select Loader esp8266_loader.py 
4. Set Xtensa cpu by hands

PS. You have to change user_rom seg_size in 61 line, because in my case when I was parsing it in line 65

(seg_addr, seg_size) = unpack_from("<II", li.read(8))

it parced wrong value and created db file about 15 GB.

I dont want to spend time for make universal solution.

