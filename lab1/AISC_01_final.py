import numpy as np

def substitute_encrypt(message, key):
    """Encrypt message using character substitution. Key is a random permutation of the 26 letters"""
    # map message to numerical array in range(0,26)
    plain = [x - ord('a') for x in map(ord,message)]
    # apply substitution according to key
    cipher = [key[x] for x in plain]
    # rewrite numerical array in uppercase letters
    cryptogram = [chr(x+ord('A')) for x in cipher]
    return ''.join(cryptogram)
    
def substitute_decrypt(cryptogram, key):
    """Decrypt cryptogram using character substitution. Key is a random permutation of the 26 letters"""
    # map cryptogram to numerical array in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # compute inverse permutation
    rev_key = np.argsort(key)
    # apply inverse substitution according to key
    plain = [rev_key[x] for x in cipher]
    # rewrite numerical array in lowercase letters
    message = [chr(x+ord('a')) for x in plain]
    return ''.join(message)

def Vigenere_encrypt(message, key):
    """Encrypt message using Vigenere algorithm. Key is a password."""
    # map message to numerical array in range(0,26)
    plain = [x - ord('a') for x in map(ord,message)]
    # map key (password) to numerical array in range(0,26)
    keynum = [x - ord('a') for x in map(ord,key)]
    # allocate empty array
    cipher = [0] * len(plain)
    i = 0
    klen = len(key)
    for k in keynum:
        # substistute one character every klen characters according to key[i]
        cipher[i::klen] = [(x + k) % 26 for x in plain[i::klen] ]
        i = i + 1
    # rewrite numerical array in uppercase letters
    cryptogram = [chr(x+ord('A')) for x in cipher]
    return ''.join(cryptogram)
    
def Vigenere_decrypt(cryptogram, key):
    """Encrypt message using Vigenere algorithm. Key is a password."""
    # map cryptogram to numerical array in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # map key (password) to numerical array in range(0,26)
    keynum = [x - ord('a') for x in map(ord,key)]
    # allocate empty array
    plain = [0] * len(cipher)
    i = 0
    klen = len(key)
    for k in keynum:
        # substistute one character every klen characters according to key[i]
        plain[i::klen] = [(x - k) % 26 for x in cipher[i::klen] ]
        i = i + 1
    # rewrite numerical array in lowercase letters
    message = [chr(x+ord('a')) for x in plain]
    return ''.join(message)

def monogram_ranking(cryptogram, topn=None):
    """Returns the topn most frequent monograms (letters) in cryptogram"""
    # map letters to numerical values in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # compute histogram of letter values
    freq = np.histogram(cipher, 26, (-0.5, 25.5))
    # get sorted letters in decreasing order of their frequency
    sorted_monograms = [(chr(x+ord('A')), freq[0][x]) for x in np.argsort(-freq[0])]
    return sorted_monograms[0:topn]

def digram_to_number(t, i):
    return 26*(ord(t[i]) - ord('A')) + ord(t[i+1]) - ord('A')
    
def number_to_digram(x):
    return ''.join([chr(x // 26 + ord('A')), chr(x % 26 + ord('A'))])

def digram_ranking(cryptogram, topn=None):
    """Returns the topn most frequent digrams (letter pairs) in cryptogram"""
    # map digrams to numerical values in range(0,26*26)
    digrams = [digram_to_number(cryptogram, i) for i in range(0,len(cryptogram)-1)]
    # compute histogram of digram values
    freq = np.histogram(digrams, 26*26, (-0.5, 26*26-0.5))
    # get sorted digrams in decreasing order of their frequency
    sorted_digrams = [(number_to_digram(x), freq[0][x]) for x in np.argsort(-freq[0])]
    return sorted_digrams[0:topn]
    
def trigram_to_number(t, i):
    return 26*26*(ord(t[i]) - ord('A')) + 26*(ord(t[i+1]) - ord('A')) + ord(t[i+2]) - ord('A')
        
def number_to_trigram(x):
    return ''.join([chr(x // (26*26) + ord('A')), chr((x % (26*26) // 26) + ord('A')), chr(x % 26 + ord('A'))])

def trigram_ranking(cryptogram, topn=None):
    """Returns the topn most frequent trigrams (letter triplets) in cryptogram"""
    # map trigrams to numerical values in range(0,26*26*26)
    trigrams = [trigram_to_number(cryptogram, i) for i in range(0,len(cryptogram)-2)]
    # compute histogram of trigram values
    freq = np.histogram(trigrams, 26*26*26, (-0.5, 26*26*26-0.5))
    # get sorted trigrams in decreasing order of their frequency
    sorted_trigrams = [(number_to_trigram(x), freq[0][x]) for x in np.argsort(-freq[0])]
    return sorted_trigrams[0:topn]

def four_ranking(c, top):
    #Aggiunto
    f=dict()
    for i in range(0,len(c)-4):
        string=c[i]+c[i+1]+c[i+2]+c[i+3]
        if string in f.keys():
            f[string]=f[string]+1
        else:
            f[string]=1
    f = sorted(f.items(), key=lambda x: -x[1])
    l=list()
    for i in range(0,top):
        l.append(f[i][0])
    return l

def crypto_freq(cryptogram):
    """Returns the relative frequencies of characters in cryptogram"""
    # map letters to numerical values in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # compute histogram of letter values
    freq = np.histogram(cipher, 26, (-0.5, 25.5))
    # return relative frequency
    return freq[0] / len(cipher)
    
def periodic_corr(x, y):
    """Periodic correlation, implemented using the FFT. x and y must be real sequences with the same length."""
    return np.fft.ifft(np.fft.fft(x) * np.fft.fft(y).conj()).real 

def main():
    #frequency of English letters in alphabetical order
    english_letter_freqs = [0.085516907,
    0.016047959,
    0.031644354,
    0.038711837,
    0.120965225,
    0.021815104,
    0.020863354,
    0.049557073,
    0.073251186,
    0.002197789,
    0.008086975,
    0.042064643,
    0.025263217,
    0.071721849,
    0.074672654,
    0.020661661,
    0.001040245,
    0.063327101,
    0.067282031,
    0.089381269,
    0.026815809,
    0.010593463,
    0.018253619,
    0.001913505,
    0.017213606,
    0.001137563]
    
    ###################################################################################
    #EXERCISE 1
    ###################################################################################
    
    with open("cryptogram01.txt","r") as text_file:
        cryptogram = text_file.read()
    
    alp=dict()
    en_alp=dict()
    fr=crypto_freq(cryptogram)
    j=0
    for i in range(ord('a'),ord('z')+1):
        alp[chr(i)]=fr[j]
        en_alp[chr(i)]=english_letter_freqs[j]
        j+=1
    sort=sorted(alp.items(), key=lambda kv: -kv[1])
    sort_en=sorted(en_alp.items(), key=lambda kv: -kv[1])
    
    sort1=dict()
    sort_en1=dict()
    for i in sort:
        sort1[i[0]]=i[1]
    for i in sort_en:
        sort_en1[i[0]]=i[1]
    
    #print(monogram_ranking(cryptogram, 3))
    #print(digram_ranking(cryptogram, 3))
    #print(trigram_ranking(cryptogram, 3))
    #print(four_ranking(cryptogram, 3))
    
    solution_cr01 = cryptogram.replace('A','w').replace('B','t').replace('C','j').replace('D','u').replace('E','x').replace('F','d').replace('G','p').replace('H','y').replace('I','c').replace('J','n').replace('K','z').replace('L','f').replace('M','g').replace('N','i').replace('O','l').replace('P','k').replace('Q','q').replace('R','o').replace('S','m').replace('T','a').replace('U','b').replace('V','s').replace('W','r').replace('X','e').replace('Y','h').replace('Z','v')
    
    print('Ex1\nThe decrypted text is: '+solution_cr01)
    print('\n')
    
    ###################################################################################
    #EXERCISE 2
    ###################################################################################
    with open("cryptogram02.txt","r") as text_file:
        cryptogram2 = text_file.read()
        
    ln_k=0 
    for i in range(5, 22):
        subsequence=cryptogram2[0::i]
        fr=crypto_freq(subsequence) 
        s=0
        for j in range(0,25):
            s+=np.power(fr[j],2)
        if(s>=0.065):
            ln_k=i
    print(ln_k)
    kloff=list()
    offsets=list()
    i=0
    #trovo gli offsets da 19 lettere l'uno
    while i<len(cryptogram2):
        offsets.append(cryptogram2[i:i+ln_k])
        i+=ln_k
    
    #dagli offset prendo la k lettera e creo le subsequences
    for i in range(0,ln_k):
        #ogni lettera i
        subs=list()
        for j in offsets:
            #di ogni offset j
            if(len(j)>i):
                subs.append(j[i])
        #subs è ora una lista delle lettere con la stessa cifratura
        #trovo la loro freq e la impongo = a fre_engl
        fr=crypto_freq(subs)
        #faccio la circular correlation per trovare il k di distanza della ceasar
        R=periodic_corr(fr, english_letter_freqs)
        maxr=-100
        #k sarà la correlazione con valore maggiore, quindi quello giusto
        k=-1
        for j in range(0,len(R)):
            if R[j]>maxr:
                maxr=R[j]
                k=j
               
        kloff.append(k+1)
        
    dictt = {'1':'a','2':'b','3':'c','4':'d','5':'e','6':'f','7':'g','8':'h',
    '9':'i','10':'j','11':'k','12':'l','13':'m','14':'n','15':'o','16':'p','17':'q',
    '18':'r','19':'s','20':'t','21':'u','22':'v','23':'w','24':'x','25':'y','26':'z'
    } 
    key=''
    for i in kloff:
        key+=dictt[str(i)]
    
    solution_cr02=Vigenere_decrypt(cryptogram2, key)
    print('Ex2\nThe key is: '+key)
    print('Decrypted text: '+solution_cr02)
    
    print('\n')


    ###################################################################################
    #EXERCISE 3
    ###################################################################################
    with open("cryptogram03.txt","r") as text_file:
        cryptogram3 = text_file.read()
    #ther is a key length?
    ln_k=0 
    for i in range(1, 9):
        subsequence=cryptogram3[0::i]
        fr=crypto_freq(subsequence) 
        s=0
        for j in range(0,25):
            s+=np.power(fr[j],2)
        if(s>=0.064):
            ln_k=i
    print(ln_k)
    kloff=list()
    offsets=list()
    i=0
    #trovo gli offsets da 8 lettere l'uno
    while i<len(cryptogram3):
        offsets.append(cryptogram3[i:i+ln_k])
        i+=ln_k
    
    #dagli offset prendo la k lettera e creo le subsequences
    for i in range(0,ln_k):
        #ogni lettera i
        subs=list()
        for j in offsets:
            #di ogni offset j
            if(len(j)>i):
                subs.append(j[i])
        #subs è ora una lista delle lettere con la stessa cifratura
        #trovo la loro freq e la impongo = a fre_engl
        fr=crypto_freq(subs)
        #faccio la circular correlation per trovare il k di distanza della ceasar
        R=periodic_corr(fr, english_letter_freqs)
        maxr=-100
        #k sarà la correlazione con valore maggiore, quindi quello giusto
        k=-1
        for j in range(0,len(R)):
            if R[j]>maxr:
                maxr=R[j]
                k=j
                
        kloff.append(k+1)
        
    dictt = {'1':'a','2':'b','3':'c','4':'d','5':'e','6':'f','7':'g','8':'h',
    '9':'i','10':'j','11':'k','12':'l','13':'m','14':'n','15':'o','16':'p','17':'q',
    '18':'r','19':'s','20':'t','21':'u','22':'v','23':'w','24':'x','25':'y','26':'z'
    } 
    key=''
    for i in kloff:
        key+=dictt[str(i)]
    
    solution_cr03=Vigenere_decrypt(cryptogram3, key)
    print('Ex3\nThe key is: '+key)
    print('Decrypted text: '+solution_cr03)
        

if __name__ == '__main__':
    main()






