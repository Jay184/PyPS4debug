from ps4debug import PS4Debugger

def main():
   debugger = PS4Debugger('192.168.2.xxx') # Assuming you are using an class C network
   processes = debugger.get_processes()

   # Search for game process
   eboot_pid = next((pid for name, pid in processes if name == 'eboot.bin'), None)
   if not eboot_pid:
      raise Exception('No eboot.bin in process list')


   # Define partials to freeze certain parameters
   get_score = partial(debugger.read_int32, pid=eboot_pid, address=0xCAB47F8)
   set_score = partial(debugger.write_int, eboot_pid, 0xCAB47F8)

   score = get_score()
   set_score(score + 99999)

   del debugger


if __name__ == '__main__':
   main()
