__author__ = 'Derog'

#This one is a pure python lybrary for UNIX crypt
import passlib.hash

def testPassSha512(cryptPass):
    crypt=passlib.hash.sha512_crypt
    salt=cryptPass[0:2]
    dictFile = open('dictionarySha512.txt','r')
    for word in dictFile.readlines():
        word=word.strip('\n')
        iterations=cryptPass.split('$')[2].split("=")[1]
        salt=cryptPass.split('$')[3]
        cryptWord=crypt.encrypt(word, salt=salt, rounds=int(iterations))
        if (cryptWord==cryptPass):
            print("[+]Foun Password: "+word)
            return
    print("[-]Password Not Found.")
    return

def PassCrackSha512():
    passFile=open('passwordsSha512.txt')
    for line in passFile.readlines():
        if ":" in line:
            user =line.split(':')[0]
            cryptPass = line.split(':')[1].strip(' ').strip('\n')
            print("[*] Cracking Password For: "+user)
            testPassSha512(cryptPass)

def testPassCrypt(cryptPass):
    crypt=passlib.hash.des_crypt
    salt=cryptPass[0:2]
    dictFile = open('dictionaryCrypt.txt','r')
    for word in dictFile.readlines():
        word=word.strip('\n')
        cryptWord=crypt.encrypt(word,salt=salt)
        if (cryptWord==cryptPass):
            print("[+]Foun Password: "+word)
            return
    print("[-]Password Not Found.")
    return

def PassCrackCrypt():
    passFile=open('passwordsCrypt.txt')
    for line in passFile.readlines():
        if ":" in line:
            user =line.split(':')[0]
            cryptPass = line.split(':')[1].strip(' ').strip('\n')
            print("[*] Cracking Password For: "+user)
            testPassCrypt(cryptPass)

if __name__=="__main__":
    PassCrackSha512()

