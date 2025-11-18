

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
import os
import os.path
def enc(key, fullpath):
    with open(fullpath, "rb+") as f:
        cipher = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))
        
        while True:
            plaintext = f.read(16)
            if not plaintext:
                break
            
            ciphertext = cipher.encrypt(plaintext)
            
            
            f.seek(-len(plaintext), 1)
            f.write(ciphertext)
    f.close()
    print(f"File {fullpath} encrypted successfully.")



key= b'\xd9#\xb8Z\xf5\xe7\xff\xd2\xac\xda\xcc\x10B\x18\x1c\xd9' 

enc(key,r"H:\file1.txt")

        