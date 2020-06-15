import binascii as basc
import sys
import re
import hmac, hashlib
from Crypto.Cipher import AES
from Crypto import Random



# Implemented using Advanced Encryption System 256 with Cipher block Chaining mode
# Cipher is computed using Plaintext + HMAC + padding
# Initilization vector and KEY are random
# Handshake not implemented 
AES_BSIZE = AES.block_size
IV = Random.new().read( AES_BSIZE )
KEY = Random.new().read( AES_BSIZE )

# padding for the CBC cipher block
def verfier_pad_or_pad(s,flag):
	l_s = len(s)
	if flag:
	    return chr((16 - l_s - 1)%16)*(16-l_s%16)
	else:
	    od = ord(s[l_s-1:])
	    m = s[0:l_s - 32 - od - 1]
	    return [s[len(m):-od - 1],hmac.new(KEY, m, hashlib.sha256).digest(),m] #hashc,hashd,msg

#Generation of Cipher text 
def performEncryption( text):
    data = text.encode()									#Encoding PlainText
    hash = hmac.new(KEY, data, hashlib.sha256).digest()		#computing hash digest using SHA256
    hash_pad = hash + verfier_pad_or_pad((data + hash),True).encode()   #padding.encode    
    cipher = AES.new(KEY, AES.MODE_CBC, IV )
    return cipher.encrypt(data + hash_pad)

def performDecryption(ciph):  # decipher a message then check if padding is good with unpad_verifier()
    dcphr = AES.new(KEY, AES.MODE_CBC, IV )
    sigc,sig2,plnTxt = verfier_pad_or_pad(dcphr.decrypt( ciph ),False)

    if sigc != sig2:
        return 0
    return plnTxt
	
#Code for attacking start from here, the attack function will decipher without knowing the key used for AES
def splitter(seq, length):
    arr_len = [seq[i:i+length] for i in range(0, len(seq), length)] 
    return arr_len

def performAttack(ipParam):
    recoveredText = []
    length_block = 16
    cnt = 1
	
    print("\n2. Performing Encryption using AES-256 Cipher Chaining Block Mode\n")
    a = performEncryption(ipParam)
    print(a)	
    len_hex_enc = len(basc.hexlify(performEncryption(ipParam)))  #length of HexForm of Bytes
    
    while(True):
        length = len(basc.hexlify(performEncryption("a"*cnt + ipParam)))
        if( len_hex_enc < length  ):
            break
        cnt = cnt + 1
    save = cnt
    v = []

	
    #Deciphering block by block
    print("\n3. Deciphering by Attacker block by block\n")
    for block in range(len_hex_enc//32-2,0,-1):
        for char in range(length_block):            
            while True:

                global IV,KEY 
                IV = Random.new().read( AES_BSIZE )                
                KEY = Random.new().read( AES_BSIZE)
                E = performEncryption("$"*16 + "#"*cnt + ipParam + "%"*(block*length_block - char))
                req = splitter(basc.hexlify(E), 32)                
                req[-1] = req[block] # last block will be designer choice                               
                plain = performDecryption(basc.unhexlify(b''.join(req).decode()))
                
                if plain != 0: # A byte found since padding is OK
                    a1 = int("0f",16)
                    a2 = int(req[-2][-2:],16)
                    a3 = int(req[block - 1][-2:],16)
                    recoveredText.append(chr(a1 ^ a2 ^ a3)) #decipher byte appended
                    tmp = recoveredText[::-1]
                    sys.stdout.write("\r Byte found %s  [ Block %02d ] : [%16s]" % (chr(a1 ^ a2 ^ a3), block, ''.join(tmp)))
                    sys.stdout.flush()
                    cnt += 1
                    break
        print('')
        cnt = save
        recoveredText = recoveredText[::-1]
        v.append(('').join(recoveredText))
        recoveredText = []
        

    v = v[::-1]
    plaintext = re.sub('^#+','',('').join(v))
    print("\n4. Deciphered plaintext:", plaintext)
    print("\n\n ***************************  Thank you ***************************\n\n ")
    return v


if __name__ == '__main__':  

    print("\n\n**********************Assignment 3 Simulation of Poodle as POC***************************\n")
    plainText = input('1. Enter PlainText\n\n')
    performAttack(plainText)
     
