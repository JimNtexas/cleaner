import shutil 
import os
import string
import argparse
from simplecrypt import encrypt, decrypt
#from Crypto.Hash import HMAC
#from Crypto.Hash import SHA256
#from Crypto.Cipher import AES
import binascii
import sys
import ntpath
import hashlib

global dbg, pwhash, src
src = ""
dbg = False
pwhash = "not a hash"

def dbg_print(txt):
    if(dbg):
        print(txt)
 
def check_pw(plain):
    hash_object = hashlib.sha1(plain.encode('utf-8'))
    hashed = hash_object.hexdigest()
    dbg_print(hashed)
    global pwhash
    pwhash = hashed
    return pwhash

def encryptfile(infile, outfile):
    print('encryt this file' + infile);
    fread = open(infile, mode='rb') #read the encrypted file
    bytes = fread.read()
    ciphertext = encrypt(pwhash, bytes) # decrypt returns bytes
    fwrite = open(outfile, mode='wb')
    fwrite.write(ciphertext)
    return

def decryptfile(infile, outfile):
    f = open(infile, mode='rb') #read the encrypted file
    bytes = f.read()
    plaintext = decrypt(pwhash, bytes)  
    f.close()
    fw = open(outfile, 'wb')
    fw.write(plaintext)
    fw.close()
    return        

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)
    
def getsrc():
    global src
    if (src == ""):
        f = open('mi.bin','rb');
        bytes = f.read()
        src = decrypt(pwhash, bytes).decode('utf-8') 
        f.close()
    return src

def clearDir(dirPath) :
	file_path = ''
	for the_file in os.listdir(dirPath):
		file_path = os.path.join(dirPath, the_file)
	try:
		if os.path.isfile(file_path):
			os.unlink(file_path)
        #elif os.path.isdir(file_path): shutil.rmtree(file_path)
	except Exception, e:
		print e
	return
    
def rmfile(tgt):
    print('removing ' + tgt)
    try:
        os.remove(tgt)
    except OSError:
        print('rmfile error')
        pass
		

     
#Main 
parser = argparse.ArgumentParser()
parser.add_argument("cmd", help="hide or restore")
parser.add_argument("pw", nargs='?', default='', help="password")
parser.add_argument("--verbose", nargs='?', default=True, help="True or False")
args = parser.parse_args()

if(args.verbose is None):
   dbg = True

print ('dbg:' + str(dbg))

def sdelete(tgt):
    print('sdeleting ' + tgt)
    os.system('sdelete -p 3 ' + tgt)

option = args.cmd
password = args.pw

while len(password) == 0:
    password = raw_input('Enter password:')
 
if args.cmd not in ('hide', 'restore'):
	print('hide or restore the file?')
	exit(1)

if not check_pw(password) :
    print("unable")
    exit(1)

getsrc()
filename = ntpath.basename(src);
 
dbg_print('mode: ' + option)

if option == 'hide':
    try:
        # clearDir('C:/Users/Jim/AppData/Roaming/mIRC/channels')
        # clearDir('C:/Users/Jim/AppData/Roaming/mIRC/logs')
        sdelete('C:/Users/Jim/AppData/Roaming/mIRC/channels *.*')
        sdelete('C:/Users/Jim/AppData/Roaming/mIRC/logs *.*')
        dbg_print('delete:' + os.getcwd())
        rmfile(filename) #delete any local copy
        print('copy:' + src)
        shutil.copyfile(src, os.getcwd()+'/'+filename)
        print('copied ' + src)
        rmfile(src) #remove the src file
    except IOError as err:
       print("I/O error: {0}".format(err))
       exit(1) 
        
    print('hide succeeded')
  
if option == 'restore':
    f = open('mdata.bin', mode='rb') #read the encrypted file
    bytes = f.read()
    plaintext = decrypt(pwhash, bytes) # decrypt returns bytes
    f.close()
    # the decrypted plaintext is bytes 
    fw = open('temp.txt', 'wb')
    fw.write(plaintext)
    fw.close()
    dbg_print('deleting:' + getsrc())
    rmfile( getsrc() ) #delete the original file
    dbg_print( 'moving to ' + getsrc() )
    shutil.move('temp.txt', getsrc())
    dbg_print('Starting target')
    os.startfile('C:\Users\Jim\ProgramFiles\mIRC\mirc.exe')


print("program exit")

    
	
	


