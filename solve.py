import time
import random
from pwn import*

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
g = 0x2
q = 0x7fffffff800000008000000000000000000000007fffffffffffffffffffffff

s = connect('103.163.25.143', 60124)

random.seed(int(time.time()))

s.recvuntil(b'Prove you know x, such that pow(2, x, 115792089210356248762697446949407573530086143415290314195533631308867097853951) == ')
y = int(s.recvline().strip().decode())
for i in range(64):
    c = random.randint(1, q-1)
    t = pow(pow(y, c, p),-1, p)
    s.sendlineafter(b't = ', str(t).encode())
    s.sendlineafter(b's = ', str(q).encode())
    print(i)
s.interactive()