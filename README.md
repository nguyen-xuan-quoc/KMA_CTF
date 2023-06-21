# KMA_CTF

# ****Discord****

```go
KMACTF{KMA_CTF_2023_D1sc0rd_ch3cK3r}
```

# ****Schnorr****

```python
import random
import time
FLAG = b'flag'

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
g = 0x2
q = 0x7fffffff800000008000000000000000000000007fffffffffffffffffffffff
assert pow(g, q, p) == 1 #g^q%p = 1

def challenge(rounds=64):
    random.seed(int(time.time()))
    x = int.from_bytes(FLAG, "big")
    y = pow(g, x, p)
    print("Prove you know x, such that pow({0}, x, {1}) == {2}".format(g, p, y))
    try:
        for i in range(rounds):
            print("[+] Round {0}/{1}".format(i+1, rounds))
            t = int(input("t = "))
            c = random.randint(1, q-1)
            print("c = {0}".format(c))
            s = int(input("s = "))
            if pow(g, s, p) == (t*pow(y, c, p)) % p: 
                continue
            else:
                return False
    except:
        return False

    return True

if __name__ == "__main__":
    is_verified = challenge()
    if is_verified:
        print(FLAG)
    else:
        print("Better luck next time, hackers!")
```

## Solution

Mấu chốt của challenge này là:

```python
random.seed(int(time.time()))
```

Hàm `random.seed()` sẽ tạo ta một bộ số ngẫu nhiên với tham số truyền vào là giá trị của `int(time.time())`. Nhưng lỗ hổng ở đây là chỉ cần ta chỉ cần lấy được giá trị của`int(time.time())`

thì sẽ recover được toàn bộ các giá trị random được sinh ra - cụ thể ở đây là 64 giá trị của `c = random.randint(1, q-1)`. Vậy việc ta cần làm là chỉ cần lấy giá trị `int(time.time())` ngay thời điểm connect với sever sau đó gửi:

```python
t = (y^c)^-1 % p
s = q
Explain:
pow(g, s, p) == (t*pow(y, c, p)) % p
=> g^q mod p == (y^c)^-1 * (y^c) % p
=> 1==1 => True
```

full code:

```python
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
#KMACTF{Pr00f_0f_Kn0wl3dg3_n0t_s0_r4nd0m_ch4ll3ng3}
```

# ****SSS Voting I****

Challenge này có thể hiểu đơn giản như sau:

Ta có tổng cộng 5 authorities và 10 voters. Mỗi voter có 5 phiếu vote, giá trị của phiếu vote sẽ là hệ số tự do (chỉ là 1 hoặc 0) của 1 đa thức được khởi tạo ngẫu nhiên, cụ thể trong challenge này là đa thức bậc 2 với các hệ số ngẫu nhiên và hệ số tự do là giá trị vote. Nhưng mỗi voter chỉ có 1 đa thức, như vậy có thể khẳng định số phiếu vote của mỗi voter có giá trị như nhau cho tất cả authorities.

Sever sẽ gửi cho chúng ta, id của từng authorities: 

```go
[+] Public ID of available authorities:
60746920731580251608655139020971111040876281799081688258941755649318979527086
15065944466486341608149240796971900992760773663209241075055762953746809182837
79529918102847796791075210040033120678592347003900954933411604834823609612115
93014849174773552948539423640337599175335497328161641206093723778732574432140
37419979466408686766898982887389613443539857548633619868820671792887135668287
```

Theo sau đó là các giá trị của `f(id)` được ghi liên kề với nhau, với f là hàm số được khởi tạo ngẫu nhiên đã nói ở trên.

```go
[+] One voter is being hacked.
Original votes (each vote is encoded in 64 hex characters):
64f6922fbbb50da51d81e4aae0c8af9399782caa64860f190c1cee2e53e00609c412d41eea5f644b5dd2f77ed40402d2db2b2cd2ccb0b9a47d46636c1be952bd011fec07f49b604e5e270f18bcf371eb7727adaf2e8015b25b5c0b1fc270ef8ae9f5dd482a9c3232921f736dcf29efeb36c14483af38875ea5d3cd503317fe208012db1e9793b3b6f3f8fdabd94bfdb7af00aa355116fdc0e52b6b19207f0644
```

Điều kiện để có được flag là làm sao cho số vote cho 3 authorities đầu tiên có giá trị là 1337. Vấn đề ở đây là chỉ có 10 người ⇒ giá trị lớn nhất của tổng số vote cũng chỉ là 30. 

⇒ Vậy, ta cần phải thay đổi hệ số tự do của f(x) sao cho tổng số vote thỏa yêu cầu trên. Ý tưởng ở đây là ta tách từng giá trị của id nhận được và cộng cho 1333

⇒ vậy f’(x) = f(x) + 1333.

Nếu hế số tự do là 1 thì hệ số tự do mới sẽ là 1334 → cần 3 người vote yes nữa thì sẽ thỏa

Nếu hế số tự do là 0 thì hệ số tự do mới sẽ là 1333 → cần 4 người vote yes nữa thì sẽ thỏa

 Như vậy ta sẽ brute force đến khi có đủ số lượng vote cần thiết.

```python
from pwn import *

while 1:
    s = connect('103.163.25.143', 60125)
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    s.recvline_startswith(b'Original votes ')
    votes = s.recvline().strip().decode()
    fake_votes = ''
    for i in range(5):
        fake_votes += str(hex((int(votes[:64], 16) + 1333)%p)[2:].zfill(64))
        votes = votes[64:]
    s.sendlineafter(b'Tampered votes:\n', fake_votes.encode())
    a = s.recv()
    print(a)
    if b'KMA' in a:
        s.interactive()
    s.close()
#b'[*] There are 1337 votes, seems like someone is hacking! :( The flag is KMACTF{p0lyn0m1al_c0nst4nt_t3rm_4s_4_s3cr3c}\n'
```

# ****SSS Voting II****
