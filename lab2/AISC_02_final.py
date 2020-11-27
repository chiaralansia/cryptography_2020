# Simplified AES using multiple rounds.
# Simplified AES maps 16-bit words in 16-bit words using a 16-bit key
# It's internal state is a 2x2 matrix of 4-bit values (nibbles)
# The input is copied onto the initial state and modified using
# AES-like transforms: AddKey, NibbleSubstitute, ShiftRow, MixColumns
# Derived from Python 3 implementation in:
#
# Author: Joao H de A Franco (jhafranco@acm.org)
#
# Description: Simplified AES implementation in Python 3
#
# Date: 2012-02-11
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
import sys
import random
import base64
import numpy as np
 
# S-Box
sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]
 
# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]
 
# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5; K3 = w6 + w7; K4 = w8 + w9;
w = [None] * 10
 
def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        # at ith iteration, if ith coeff of p2 is set, add p1*x^i mod x^4+x+1 to result
        if p2 & 0b1:
            p ^= p1
        # compute p1 = p1*x mod x^4+x+1
        p1 <<= 1
        # if degree of p1 is > 3, subtract x^4+x+1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111
 
def intToVec(n):
    """Convert a 2-byte integer into a 4-nibble vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]
 
def vecToInt(m):
    """Convert a 4-nibble vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
 
def addKey(s1, s2):
    """Add two keys in GF(2^4)"""
    return [i ^ j for i, j in zip(s1, s2)]
     
def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]
     
def shiftRow(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]
    
def mixCol(s):
    """Defined as [1 4; 4 1] * [s[0] s[1]; s[2] s[3]] in GF(2^4)/x^4 + x + 1"""
    return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]), s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]

def iMixCol(s):
    """Defined as [9 2; 2 9] * [s[0] s[1]; s[2] s[3]] in GF(2^4)/x^4 + x + 1"""
    return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]), mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
 
def keyExp(key):
    """Generate the round keys (up to 4 rounds)"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)
 
    Rcon1, Rcon2, Rcon3, Rcon4 = 0b10000000, 0b00110000, 0b01100000, 0b11000000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]
    w[6] = w[4] ^ Rcon3 ^ sub2Nib(w[5])
    w[7] = w[6] ^ w[5]
    w[8] = w[6] ^ Rcon4 ^ sub2Nib(w[7])
    w[9] = w[8] ^ w[7]
    

def computeRound(subkey0, subkey1, state):
    # generic round: NS-SR-MC-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = mixCol(state)
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    return state
    
def computeInvRound(subkey0, subkey1, state):
    # generic inverse round: AK-MC-SR-NS
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    state = iMixCol(state)
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    return state
    
 
def encrypt(ptext):
    """Encrypt plaintext block (2 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[4] << 8) + w[5]), state)
    
    return vecToInt(state)
     
def encrypt2(ptext):
    """Encrypt plaintext block (3 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    #second round
    state = computeRound(w[4], w[5], state)
    
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[6] << 8) + w[7]), state)
    
    return vecToInt(state)

def encrypt3(ptext):
    """Encrypt plaintext block (4 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    #second round
    state = computeRound(w[4], w[5], state)
    #third round
    state = computeRound(w[6], w[7], state)
    
    #third round
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[8] << 8) + w[9]), state) 
    return vecToInt(state)

def encryptLazy(ptext):
    """Encrypt plaintext block (4 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[2] << 8) + w[3]), state) 
    
    #second round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[4] << 8) + w[5]), state) 
    
    #third round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[6] << 8) + w[7]), state) 
    
    
    #third round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[8] << 8) + w[9]), state) 
    return vecToInt(state)
def encryptVeryLazy(ptext):
    """Encrypt plaintext block (4 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = sub4NibList(sBox, state)
    #state = addKey(intToVec((w[0] << 8) + w[1]), state) 
    
    #second round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state) 
    
    #third round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state) 
    
    
    #third round
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state) 
    

    return vecToInt(state)
def decrypt(ctext):
    """Decrypt ciphertext block (2 rounds)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[4] << 8) + w[5]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    # invert first round
    state = computeInvRound(w[2], w[3], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

    
def encrypt_foo(ptext):
    """Encrypt plaintext block"""
        
    # last round: NS-SR-AK
    state = sub4NibList(sBox, intToVec(ptext))
    state = shiftRow(state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)
    
def find_key(ptext,ctext):
    state = sub4NibList(sBox, intToVec(ptext))
    state = shiftRow(state)
    
    key = addKey(intToVec(ctext), state)
    
    return key
    
 
def decrypt_foo(ctext,keyF):
    """Decrypt ciphertext block"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    
    return vecToInt(state)


def hamming (x, y):
    return bin(x ^ y).count('1')
    
 
if __name__ == '__main__':
    # Test vectors from "Simplified AES" (Steven Gordon)
    # (http://hw.siit.net/files/001283.pdf)
     
    hammingD=np.zeros(1000)
    hammingD3=np.zeros(1000)
    hammingD4=np.zeros(1000)
    hammingDl=np.zeros(1000)
    hammingDvl=np.zeros(1000)
    key = random.getrandbits(16)
    keyExp(key)
    for i in range(1000):
        plaintext = random.getrandbits(16)
        error = 1 << random.randrange(16)
        plaintext2 = plaintext ^ error
        ciphertext = encrypt(plaintext)
        ciphertext2 = encrypt(plaintext2)
        ciphertext3 = encrypt2(plaintext)
        ciphertext23 = encrypt2(plaintext2)
        ciphertext4 = encrypt3(plaintext)
        ciphertext24 = encrypt3(plaintext2)
        ciphertextl = encryptLazy(plaintext)
        ciphertext2l = encryptLazy(plaintext2)
        ciphertextvl = encryptVeryLazy(plaintext)
        ciphertext2vl = encryptVeryLazy(plaintext2)
        hammingD[i]=hamming(ciphertext, ciphertext2)
        hammingD3[i]=hamming(ciphertext3, ciphertext23)
        hammingD4[i]=hamming(ciphertext4, ciphertext24)
        hammingDl[i]=hamming(ciphertextl, ciphertext2l)
        hammingDvl[i]=hamming(ciphertextvl, ciphertext2vl)
        
    
    print('Mean fixed key, random plaintext: two rounds '+str(np.mean(hammingD)))
    print('\t\t\t\t  three rounds '+str(np.mean(hammingD3)))
    print('\t\t\t\t  four rounds '+str(np.mean(hammingD4)))
    print('\t\t\t\t  four lazy rounds '+str(np.mean(hammingDl)))
    print('\t\t\t\t  four very lazy rounds '+str(np.mean(hammingDvl)))
    
    
    hammingD2=np.zeros(1000)
    hammingD23=np.zeros(1000)
    hammingD24=np.zeros(1000)
    hammingD2l=np.zeros(1000)
    hammingD2vl=np.zeros(1000)
    keyToChange = random.getrandbits(16)
    keyExp(keyToChange)
    plaintextF = random.getrandbits(16)
    ciphertextF = encrypt(plaintextF)
    ciphertextF3 = encrypt2(plaintextF)
    ciphertextF4 = encrypt3(plaintextF)
    ciphertextFl = encryptLazy(plaintextF)
    ciphertextFvl = encryptVeryLazy(plaintextF)
    for i in range(1000):
        error = 1 << random.randrange(16)
        key2 = keyToChange ^ error
        keyExp(key2)
        ciphertext2C = encrypt(plaintextF)
        ciphertext2C3 = encrypt2(plaintextF)
        ciphertext2C4 = encrypt3(plaintextF)
        ciphertext2Cl = encryptLazy(plaintextF)
        ciphertext2Cvl = encryptVeryLazy(plaintextF)

        hammingD2[i]=hamming(ciphertextF, ciphertext2C)
        hammingD23[i]=hamming(ciphertextF3, ciphertext2C3)
        hammingD24[i]=hamming(ciphertextF4, ciphertext2C4)
        hammingD2l[i]=hamming(ciphertextFl, ciphertext2Cl)
        hammingD2vl[i]=hamming(ciphertextFvl, ciphertext2Cvl)
    
    print('Mean fixed plaintext, random key: two rounds'+str(np.mean(hammingD2)))
    print('\t\t\t\t  three rounds '+str(np.mean(hammingD23)))
    print('\t\t\t\t  four rounds '+str(np.mean(hammingD24)))
    print('\t\t\t\t  four lazy rounds '+str(np.mean(hammingD2l)))
    print('\t\t\t\t  four very lazy rounds '+str(np.mean(hammingD2vl)))
######
##########Seconda parte
#########

    print('\n\nSecond exercise: decrypt_foo\n\n')
    with open("ciphertext.txt", "r") as text_file:         
        encryption = base64.b64decode(text_file.read())
        
    #print(encryption)
    ciphertext = (encryption[0] << 8) + encryption[1]
    b=bin(int.from_bytes(encryption,byteorder='little'))
    binario=int.from_bytes(encryption,byteorder='little')
    lenght=int(len(b)/16)
    lenght=((lenght+1)*16)+2
    binario=format(binario,'#0'+str(lenght)+'b')
    #print(((len(bin(binario))/16)+1)*16+2+'b')
    #binario=format(binario, '#0'+str(int(((len(bin(binario))/16)+1)*16+2))+'b')
               
    #print(binario)

    known_plain = 0b0111001001101110
    known_cipher = 0b0010111000001101 
    keyF=find_key(ciphertext,ciphertext)
    res=list()
    i=len(binario)
    while(i>3):
        #print(binario[i-8:i]+"/"+binario[i-16:i-8])
        p=binario[i-8:i]+binario[i-16:i-8]
        #print(p)
        p=int(p,2)
        res.append(decrypt_foo(p,keyF))
        i=i-16
    r=''
    for i in res[:-1]:
        i=format(i,"#018b")
        r+=chr(int(i[2:10],2))+chr(int(i[10:18],2))
    print(r)
    
    
    
    
    

       
    sys.exit()




