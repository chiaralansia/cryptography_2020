import hashlib
import os
import secrets

aU = int.from_bytes(b"it is the constant a", byteorder='little')
bU = int.from_bytes(b"it is the constant b", byteorder='big')

# sample DSA parameters for 1024-bit key from RFC 6979
pDSA = 0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779
qDSA = 0x996F967F6C8E388D9E28D01E205FBA957A5698B1
gDSA = 0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD
m2=''

def egcd(a, b):
    """computes g, x, y such that g = GCD(a, b) and x*a + y*b = g"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(a, m):
    """computes a^(-1) mod m"""
    g, x, y = egcd(a % m, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def main():
    
    message = b"SHA-256 is a cryptographic hash function"
    
    #UNO
    m = hashlib.sha256()
    for i in range(0,10):
        x1, x2 = HashFunct(UniversalHash,4)

    h=UniversalHash(message,20)
    Preimage(h,20)
    print(Preimage(h,20))
    
    """
    #DUE prima parte
    x=secrets.randbelow(qDSA-1) #private key
    y=pow(gDSA,x,pDSA) #public key
    #print(y)
    (r,s)=SchnorrSign(x,message)
    #print('Signature :\nr =',r,'\ns =',s)
    #print('Verification : ',signatureVerification(r,s,y,message))
    """
    """
    #DUE seconda parte
    y_prof=42276637486569720268071647368550139276503521977640661888834825275517477780979914414339836061961635727800848465170706694019279805873893995587354694642526839889426158621140802827015533730771103146644607587713359225607432856473853326971226628964711099095487586928079612107255097386799478803704960241864601625828
    message1 = b'first message'
    (r1,s1) = (299969984114895304388954029424480730263471439206, 192417049713099740312922361446986628497439105550)
    message2 = b'second message'
    (r2,s2) = (719970963765961216949252326232207427282652913363, 107425968460827725118970802806887322358870342520)
    q=qDSA
    private=0
    
    for i in range(1,101):
        k=(s1+r1*(i*modinv(r2,q)-s2*modinv(r2,q)+q))%q*modinv(1-r1*modinv(r2,q),q)+q
        x=(k+i-s2)*modinv(r2,q)+1*q
        (r_1,s_1)=SchnorrSign(x,message1)
        #print('k=',k,'\nx=',x,'\nr=',r,'\ns=',s)
        if signatureVerification(r_1,s_1,y_prof,message1)==True:
            print('Find!')
            private=x
            (r_2,s_2)=SchnorrSign(x,message2)
            #print('k=',k,'\nx=',x,'\nr=',r,'\ns=',s)
            if signatureVerification(r_2,s_2,y_prof,message2)==True:
                print('Find2!')
     
    message1 = b'first message'           
    (r_pk,s_pk)=SchnorrSign(private,message1)
    print('Signature :\nr =',r_pk,'\ns =',s_pk)
    print('Verification : ',signatureVerification(r_pk,s_pk,y_prof,message1))
    """
    #BONUS
    '''
    message = b"SHA-256 is a cryptographic hash function"
    x=secrets.randbelow(qDSA-1) #private key
    y=pow(gDSA,x,pDSA) #public key
    #print(y)
    (r,s,h)=SchnorrSign2(x,message)
    print('Verification : ',signatureVerification2(r,s,y,message))
    flag,m2= Preimage(h,20)
    nbytes = (m2.bit_length()+7)//8
    m2 = m2.to_bytes(nbytes, byteorder='big')
    print('Verification : ',signatureVerification2(r,s,y,m2))
    (r1,s1,h)=SchnorrSign2(x,m2)
    print('Verification : ',signatureVerification2(r1,s1,y,m2))
    if r==r1 & s==s1:
        print('Sbagliato')
    #print('Signature :\nr =',r,'\ns =',s)
    '''
    
def SchnorrSign(x,message):
    k = secrets.randbelow(qDSA-1)
    I = pow(gDSA,k,pDSA)
    nbytes = (pDSA.bit_length()+7)//8
    I_bytes = I.to_bytes(nbytes, byteorder='big')
    conc = I_bytes + message
    h = int.from_bytes(hashing(conc,32), byteorder='big')
    r = h%qDSA
    s = (k-r*x)%qDSA
    return r,s

def signatureVerification(r,s,y,message):
    I = (pow(gDSA,s,pDSA)*pow(y,r,pDSA))%pDSA
    nbytes = (pDSA.bit_length()+7)//8
    I_bytes = I.to_bytes(nbytes, byteorder='big')
    conc = I_bytes+message
    h1 = int.from_bytes(hashing(conc,32), byteorder='big')
    r1 = h1%qDSA
    return r1==r


def SchnorrSign2(x,message):
    k = secrets.randbelow(qDSA-1)
    I = pow(gDSA,k,pDSA)
    nbytes = (pDSA.bit_length()+7)//8
    I_bytes = I.to_bytes(nbytes, byteorder='big')
    conc = I_bytes + message
    h=UniversalHash(conc,20)
    h2 = int.from_bytes(UniversalHash(conc,20), byteorder='big')
    r = h2%qDSA
    s = (k-r*x)%qDSA
    return r,s,h

def signatureVerification2(r,s,y,message):
    I = (pow(gDSA,s,pDSA)*pow(y,r,pDSA))%pDSA
    nbytes = (pDSA.bit_length()+7)//8
    I_bytes = I.to_bytes(nbytes, byteorder='big')
    conc = I_bytes+message
    h1 = int.from_bytes(UniversalHash(conc,20), byteorder='big')
    
    r1 = h1%qDSA
    return r1==r


   
def hashing(x,size):
    m=hashlib.sha256()
    m.update(x)
    h=m.digest()[:size]
    return h

def HashFunct(func,size):
    x0 = secrets.randbits(size*8+8)
    x0 = bytearray(bin(x0),'utf-8')
    C1=0
    C2=0
    x1=func(x0,size)
    x2=func(x1,size)
    while x1 != x2:
        C1 += 1
        x1=func(x1,size)
        x2=func(func(x2,size),size)
    x1 = x0
    while func(x1,size) != func(x2,size):
        C2 += 1
        x1=func(x1,size)
        x2=func(x2,size)
    print(C1,C2)
    return x1, x2   

def UniversalHash(message,size):
    m=int.from_bytes(message, byteorder='big')
    q=qDSA
    a=aU
    b=bU
    h=(a*m+b)%q
    return h.to_bytes(20, byteorder='big')[:size]

def Preimage(hash1,size):
    q = qDSA
    a = aU
    b = bU

    h=int.from_bytes(hash1, byteorder = 'big')
    m2=-1
    n=10
    while m2<0:
        m2=(h-b)*modinv(a,q)+n*q
        n=n*10
    print("m2: "+str(m2))
    
    digest2 = (a*m2 + b)%q
    digest1=h

    
    if digest2==digest1:
        print("Preimage found!")
    else:
        print("Preimage NOT found!")
        print("Digest 1: " + str(digest1))
        print("Digest 2: " + str(digest2))

    return (digest2==hash1),m2
        

if __name__ == '__main__':
    main()
