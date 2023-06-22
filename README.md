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

Điều kiện để có được flag là làm sao cho số vote cho 3 authorities đầu tiên có giá trị là 1337. Vấn đề ở đây là chỉ có 10 người ⇒ giá trị lớn nhất của tổng số vote cũng chỉ là 30. Nhưng vì mỗi người chỉ có 1 đa thức mà hàm `lagrange_interpolate()` sẽ tính hệ số tự do tại đa thức:
```
g(x) = f0(x) + f1(x) + ... + f9(x)
với mỗi fi(x) là 1 đa thức riêng của từng voter
```
Như vậy giá trị lớn nhất của hệ số tự do hàm g(x) chỉ là 10.

⇒ Vậy, ta cần phải thay đổi hệ số tự do của f(x) được cung cấp sao cho tổng số vote thỏa yêu cầu trên. Ý tưởng ở đây là ta tách từng giá trị của id nhận được và cộng cho 1333

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

Thuật toán hoạt động tương tự bài trên. Nhưng thay vì gửi cho ta votes của voter thì lần này ra nhận được votes của 1 authorites. 

Ta sẽ qui ước như sau:

```go
voter[0] - f0(x)
voter[1] - f1(x)
voter[2] - f2(x)
...
voter[9] - f9(x)
```

Như vậy, kết quả của sever trả cho ta sẽ có dạng:

```go
[+] Authority id[0] is being hacked.
f0(id[0])|f1(id[0])|...|f9(id[0]) -> y0|y1|...|y9
```

Phân tích hàm `lagrange_interpolate()`:

```go
func lagrange_interpolate(ids, votes []*big.Int) *big.Int {
	p := new(big.Int).SetBytes([]byte{255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	if len(ids) != len(votes) {
		return nil
	}
	sum := big.NewInt(0)
	for i := 0; i < len(votes); i++ {
		tmp := votes[i]
		for j := 0; j < len(ids); j++ {
			if i != j {
				neg := new(big.Int).Neg(ids[j])
				neg.Add(neg, p)
				tmp.Mul(tmp, neg)
				neg.Add(neg, ids[i])
				neg.ModInverse(neg, p)
				tmp.Mul(tmp, neg)
			}
		}
		sum.Add(sum, tmp)
		sum.Mod(sum, p)
	}
	return sum
}
```

Biểu thức tổng quát nhìn chung sẽ có dạng như sau:

```go
y = (votes[0] * (p - ids[1]) * (p - ids[2])) / ((p + ids[0] - ids[1]) * (p + ids[0] - ids[2])) +
    (votes[1] * (p - ids[0]) * (p - ids[2])) / ((p + ids[1] - ids[0]) * (p + ids[1] - ids[2])) +
    (votes[2] * (p - ids[0]) * (p - ids[1])) / ((p + ids[2] - ids[0]) * (p + ids[2] - ids[1]))
```

Như đã nói ở trên, kết quả thu được sẽ có giá trị tối đa là 10:

Ý tưởng ở đây là biến đổi biểu thức từ những giá trị ta có để `y` thành `y + 1333` (tương tự challenge trên).

Phân tích một chút về số hạng đầu tiên của y.

```go
a = (votes[0] * (p - ids[1]) * (p - ids[2])) / ((p + ids[0] - ids[1]) * (p + ids[0] - ids[2]))
```

Theo qui ước trên:

$votes[0] = f_0(id[0]) + f_1(id[0])+...+f_9(id[0])$

Như vậy, bằng các giá trị được sever cung cấp ta hoàn toàn có thể tính được `votes[0]` nhưng mục đích chính là biển đổi `a` thành `a + 1333`. Các authorities sẽ bị Shuffle trước khi tính `y`, nhưng sever vẫn cung cấp cho ta id của 1 authorities bị hack. 

Gỉa sử, sau khi Shuffle vị trí của 3 id tiền tiên là.

```go
id_hacked||id[1]||id[2]
```

Vậy a sẽ có dạng như sau:

```go
a = (votes[0] * (p - ids[1]) * (p - ids[2])) / ((p - ids[1] + id_hacked) * (p - ids[2] + id_hacked))
```

ta sẽ đổi `f9(id_hacked)` thành 

```go
f9(id_hacked) + 1333* [(p - ids[1]) * (p - ids[2])) / ((p - ids[1] + id_hacked) * (p - ids[2] + id_hacked))]^-1
```

Vậy sau khi đổi f9(id_hacked), `a` sẽ thành `a + 1333` → `y` thành `y + 1333` với điều kiện kết quả sau khi Shuffle phải có dạng ta đã qui ước. Vì sau khi lấy id_hacked ra thì chỉ còn 4 id khác nên việc brute force là hoàn toàn khả thi.

Full code:

```go
from pwn import *
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951

while 1:
    s = connect('103.163.25.143', 60126)
    ids = []
    s.recvline_startswith(b'[+] Public ID of available authorities:')
    for i in range(5):
        ids.append(int(s.recvline().strip().decode()))
    id_hacked = int(s.recvline_startswith(b'[+] Authority').strip().decode().split(' ')[-4])
    ids.remove(id_hacked)
    tmp = (p - ids[1])*(p - ids[2]) % p
    tmp = tmp*pow((p - ids[1] + id_hacked)*(p - ids[2] + id_hacked), -1, p) % p
    s.recvline_startswith(b'Original votes ')
    votes = s.recvline().strip().decode()
    fake_votes = ''
    fake_votes = votes[:-64]
    fake_votes += str(hex(((int(votes[-64:], 16)) + 1333*pow(tmp, -1, p))%p))[2:].zfill(64)
    s.sendlineafter(b'Tampered votes:\n', fake_votes.encode())
    a = s.recv()
    print(a)
    if b'KMA' in a:
        s.interactive()
    s.close()
#b'[*] There are 1337 votes, seems like someone is hacking! :( The flag is KMACTF{c0ngr4ts!_h4ck3r_:grin:_:grin:_:grin:}\n'
```

# ****Only Lord Can Go REVENGE****

```go
from Crypto.Util.number import *
import random

print(
"""
     )      (           (       )                   (       )                
  ( /(  (   )\ )  (     )\ ) ( /(   *   )  *   )    )\ ) ( /(             )  
  )\()) )\ (()/(  )\   (()/( )\())` )  /(` )  /((  (()/( )\())  (   (  ( /(  
|((_)\(((_) /(_)|((_)   /(_)|(_)\  ( )(_))( )(_))\  /(_)|(_)\   )\  )\ )(_)) 
|_ ((_)\___(_)) )\___  (_))   ((_)(_(_())(_(_()|(_)(_))__ ((_) ((_)((_|(_)   
| |/ ((/ __/ __((/ __| | |   / _ \|_   _||_   _| __| _ \ \ / / \ \ / /|_  )  
  ' < | (__\__ \| (__  | |__| (_) | | |    | | | _||   /\ V /   \ V /  / /   
 _|\_\ \___|___/ \___| |____|\___/  |_|    |_| |___|_|_\ |_|     \_/  /___|  
                                                                             
"""
)

m = 94472212093594626131047436978697575439604582025155253003497324934058676105592120465477333165162440542344704938026733015754449262871298725480530709273109987324093054515772972278276237630988938655113525659250415319555533704569076292929214171706312390225710667281502861122029038648478773963282271762064453388333
a = getPrime(128)
b = getPrime(256)
c = getPrime(512)
d = random.randrange(1,m)
e = random.randrange(1,m)

print("I will give u only 4 lucky numbers :>")
for i in range(4):
    y = (a*d + b*e + c) % m
    print(f"Lucky number {i+1}: {y}")
    e = d
    d = y

print("Now show off your guessing skills, ego ._.")

for i in range(23):
    y = (a*d + b*e + c) % m
    guess = int(input("Guess: "))
    if guess == y:
        print(f'Nai xuw !!! Remain: {23-i-1}/23')
    else:
        print("Luck is only for those who try, if you don't understand that, then get out !!!")
        exit(0)
    e = d
    d = y

print("WOW, I rly want how do u can guess all correctly, plz sharing w me :<")
print('KMACTF{mao_phac?}')
```

## Solution

Biểu thức tổng quát có dạng như sau:

```go
Lucky number 1: y1 = (a * d  + b * e  + c) mod m
Lucky number 2: y2 = (a * y1 + b * d  + c) mod m
Lucky number 3: y3 = (a * y2 + b * y1 + c) mod m
Lucky number 4: y4 = (a * y3 + b * y2 + c) mod m
```

Ta có: 

```go
y4 - y3 = (a(y3-y2) + b(y2-y1)) mod m
=> y4 - y3 = a(y3-y2) + b(y2-y1) + k*m
```

Thiết lập lattice:

```go
v1 = [y2-y1, 1, 0, 0]
v2 = [y3-y2, 0, 1, 0]
v3 = [y4-y3, 0, 0, 1]
v4 = [m    , 0, 0, 0]
=> Lattice
L = {a1*v1 + a2*v2 + ... + ak*vk : a1, a2, ..., an ∈ Z}.
```

Vector ta muốn tìm sẽ có dạng:

```go
-b*b1 - a*v2 + v3 - k*v4 = (0, -b, -a, 1)
```

Nhưng vì `a, b, c` là các số khá lớn nên để chắc chắn tìm được vector có dạng như trên ta sẽ thêm trọng số là `2^1024` vào một số giá trị trên. 

Lattice mới sẽ có dạng như sau:

```go
v1 = [(y2-y1)*2^1024, 1, 0, 0]
v2 = [(y3-y2)*2^1024, 0, 1, 0]
v3 = [(y4-y3)*2^1024, 0, 0, 2^1024]
v4 = [m*2^1024      , 0, 0, 0]
=> Lattice
L = {a1*v1 + a2*v2 + ... + ak*vk : a1, a2, ..., an ∈ Z}.
=> vector can tim: 
(0, -b, -a, 2^1024)
```

full code:

```go
from pwn import *
from sage.all import *

r = remote('103.163.25.143', 60127)

y_arr = []
for i in range(4):
    r.recvuntil(f'Lucky number {i+1}: '.encode())
    y = int(r.recvline())
    y_arr.append(y)

m = 94472212093594626131047436978697575439604582025155253003497324934058676105592120465477333165162440542344704938026733015754449262871298725480530709273109987324093054515772972278276237630988938655113525659250415319555533704569076292929214171706312390225710667281502861122029038648478773963282271762064453388333
M = Matrix([
  [(y_arr[1] - y_arr[0])*(2**1024), 1, 0, 0], 
  [(y_arr[2] - y_arr[1])*(2**1024), 0, 1, 0], 
  [(y_arr[3] - y_arr[2])*(2**1024), 0, 0, (2**1024)], 
  [m*(2**1024), 0, 0, 0],
])

L = M.LLL()
b,a = abs(L[3][1]), abs(L[3,2])
c = (y_arr[3] - a*y_arr[2] - b*y_arr[1]) % m
print(c)

assert is_prime(a) and is_prime(b) and is_prime(c)
print(f'[+] FOUND a,b,c !!!')
print(f'[+] {a = }')
print(f'[+] {b = }')
print(f'[+] {c = }')

for i in range(23):
    y = (a*y_arr[-1] + b*y_arr[-2] + c) % m
    r.sendlineafter(b'Guess: ', str(y).encode())
    print(r.recvline())
    y_arr.append(y)

r.interactive()
'''
WOW, I rly want how do u can guess all correctly, plz sharing w me :<
KMACTF{LLL_c0m3_b4ck_t0_KMA_?}
'''
```
