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
