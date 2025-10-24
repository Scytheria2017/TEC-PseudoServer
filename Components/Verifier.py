import hashlib
import os

# -----------------
# SRP6 Verification
# -----------------

def verify(account):
        
    SRP6N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)

    credentials = f"{account.upper()}:{account.upper()}".encode('utf-8')
    salt = os.urandom(32)
        
    x = hashlib.sha1(salt + hashlib.sha1(credentials).digest()).digest()
    x = int.from_bytes(x, 'big')
        
    return pow(7, x, SRP6N)


def make_key(verif):

    SRP6N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)

    key_rand = int.from_bytes(os.urandom(32), 'big')
    return ((3 * verif + pow(3, key_rand, SRP6N)) % SRP6N)

