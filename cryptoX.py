import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import Crypto.Util.Counter
import sys
import dropbox
import mysql.connector
from mysql.connector import errorcode
import getpass
import string
import random

#Key Generation
def generate_RSA(bits): 
  new_key = RSA.generate(2048, e=65537)
  public_key = new_key.publickey().exportKey("PEM")
  private_key = new_key.exportKey("PEM")
  public_file = open('KeyImp.pem', 'wb')
  public_file.write(public_key)
  private_file = open('KeyImpPri.pem', 'wb')
  private_file.write(private_key)

config = {
   'user': 'root',
   'password': '',
   'host': '127.0.0.1',
   'database': 'cryptox',
   'raise_on_warnings': True,
   'buffered' : True,
}
cnx = mysql.connector.connect(**config)
uploadFilename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))

client = dropbox.client.DropboxClient('CQYiEFlmyhoAAAAAAAAACLEQ_2I67RW_kLEwsLOU6zjYOsBrj4t1L2EAFeUyb0nt')
def hilite(string, status, bold):
    attr = []
    if status:
        # green
        attr.append('32')
    else:
        # red
        attr.append('31')
    if bold:
        attr.append('1')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
print ''
print '                                                     ----------------------------------------------------------------------------------------------------'
print ''
print ''
print '                                                                                    _____                  _      __   __'
print '                                                                                   / ____|                | |     \ \ / /'
print '                                                                                  | |     _ __ _   _ _ __ | |_ ___ \ V / '
print "                                                                                  | |    | '__| | | | '_ \| __/ _ \ > <"  
print "                                                                                  | |____| |  | |_| | |_) | || (_) / . \\"
print "                                                                                   \_____|_|   \__, | .__/ \__\___/_/ \_\\"
print "                                                                                                __/ | |                  "
print "                                                                                               |___/|_|                  "
print ''
print '                                                                                                v1.0'
print''
print '                                                                        Authors: Vinmay Nair, Rishikesh Walawalkar, Swapnil Kadam'
print''
print '                                                     ----------------------------------------------------------------------------------------------------'

if(sys.argv[1] == 'install'):  
  if not os.path.isfile('keyImp.pem') and not os.path.isfile('keyImpPri.pem'):
    directory = 'downloads'
    generate_RSA(2048)    
    
    if not os.path.exists(directory):
      os.makedirs(directory)      
    print ''
    print '                                                                                       CryptoX is ready to be used.'
  else:
    print ''
    print '                                                                                       CryptoX is already installed.'

elif(sys.argv[1] == 'register'):
  cursor = cnx.cursor()
  cursor.execute("select uname from user where uname ='" + sys.argv[2] + "'")
  if cursor.rowcount == 0:    
    pswd = sys.argv[3]
    add_info = ("INSERT INTO user (uname,pass) VALUES (%s , %s)")
    data_info = (sys.argv[2], SHA256.new(sys.argv[3]).hexdigest())
    cursor.execute(add_info, data_info)
    cnx.commit()
    print '                                                                                             User is registered'
  else:
    print '                                                                             User already present. Please use a different username'

elif(sys.argv[1] == "-u"):
  cursor = cnx.cursor()
  cursor.execute("select uname,pass from user where uname ='" + sys.argv[2] + "'")  
  row = cursor.fetchone()
  if cursor.rowcount == 0:
    sys.exit('                                                                                       Username not registered')

  else:
    if row[1] == SHA256.new(sys.argv[3]).hexdigest():
      msgbool = 0
      #SHA256 Hashing of the file
      file2 = open(sys.argv[4], 'rb')
      myText = file2.read()      
      SHA256.digest_size = 32
      keySHA = SHA256.new(myText).digest()
      keySHAHex = SHA256.new(myText).hexdigest()

      #AES Encryption in Counter mode
      secret = 8 *'0\x00'
      crypto = AES.new(keySHA, AES.MODE_CTR, counter=lambda: secret)
      encrypt = crypto.encrypt(myText)

      #RSA-OAEP of the key
      public_key = open('KeyImp.pem').read()
      keyRSA = RSA.importKey(public_key)
      cipher = PKCS1_OAEP.new(keyRSA)
      ciphertext = cipher.encrypt(keySHA)
     
      #MySQL DB Operations
      try:    
        cursor = cnx.cursor()
        cursor.execute("Select hashvalue,digest from crypto where hashvalue='" + keySHAHex + "'")
        row = cursor.fetchone()
        if cursor.rowcount == 0:
          
          #File creation AES
          fileAES = open('temp','w+')
          response = client.put_file(uploadFilename, encrypt, True)
          fileAES.close()
          os.remove('temp')

          #File creation RSA-OAEP
          fileSHA = open('temp','w+')
          response = client.put_file(uploadFilename + '-' + sys.argv[2], keySHA , True)
          fileSHA.close()
          os.remove('temp')

          add_info = ("INSERT INTO crypto (username, hashvalue, filename, digest) VALUES (%s, %s, %s, %s)")
          data_info = (sys.argv[2],keySHAHex,file2.name, uploadFilename)
          cursor.execute(add_info, data_info)
          cnx.commit()
        else:    
          cursor.execute("Select username,hashvalue from crypto where hashvalue='" + keySHAHex + "' and username = '" + sys.argv[2] + "'")
          if cursor.rowcount == 0:
            add_info = ("INSERT INTO crypto (username, hashvalue, filename, digest) VALUES (%s, %s, %s, %s)")
            data_info = (sys.argv[2],keySHAHex,file2.name, row[1])
            cursor.execute(add_info, data_info)
            cnx.commit()
            #File creation RSA-OAEP
            fileSHA = open('temp','w+')
            response = client.put_file(row[1] + '-' + sys.argv[2], keySHA , True)
            fileSHA.close()
            os.remove('temp')
          else:
            cursor.execute("Select username,filename from crypto where username='" + sys.argv[2] + "' and filename = '" + file2.name + "'")
            if cursor.rowcount != 0:
              message = hilite('                                     Filename Already Present', 1, 1)
              msgbool = 1
            else:
              add_info = ("INSERT INTO crypto (username, hashvalue, filename, digest) VALUES (%s, %s, %s, %s)")
              data_info = (sys.argv[2],keySHAHex,file2.name, row[1])
              cursor.execute(add_info, data_info)
              cnx.commit()
              #File creation RSA-OAEP
              fileSHA = open('temp','w+')
              response = client.put_file(row[1] + '-' + sys.argv[2], keySHA , True)
              fileSHA.close()
              os.remove('temp')
      except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
          print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
          print("Database does not exists")
        else:
          print(err)
      else:
        cnx.close()

      if msgbool == 0:
        print '                                                                                      Encryption Completed'
        print '                                                           You file ' + file2.name + ' has been successfully encrypted and uploaded.'
      else:
        print ''
        print message
      file2.close()
    else:
      print '                                                                       Password did not match. Please enter the valid password.'
elif(sys.argv[1] == "-d" and sys.argv[2] == 'shared'):
  cursor = cnx.cursor()
  cursor.execute("select uname,pass from user where uname ='" + sys.argv[3] + "'")  
  row = cursor.fetchone()
  if cursor.rowcount == 0:
    sys.exit('Username not registered')

  else:
    if row[1] == SHA256.new(sys.argv[4]).hexdigest():
      cnx = mysql.connector.connect(**config)
      cursor = cnx.cursor()
      cursor.execute("Select hashvalue,filename,digest,sentby from sharedfiles where username='" + sys.argv[3] + "' and filename = '" + sys.argv[5] + "'")
      if cursor.rowcount != 0:
        row = cursor.fetchone()
        secret = 8 *'0\x00'
        decrypt = AES.new(row[0].decode("hex"), AES.MODE_CTR, counter=lambda: secret)
        f, metadata = client.get_file_and_metadata(row[2])
        out = open('downloads\\' + row[1], 'wb+')
        data = decrypt.decrypt(f.read())
        out.write(data)
        print ""
        print ""
        print '                                                                        Downloaded the file' + row[1] + 'shared by ' + row[3]
      else:
        print '                                                        File not found. Check if the file name is correct or if this file is uploaded or not.'
    else:
      print '                                                                                   Please enter the correct password.'

elif(sys.argv[1] == "-d"):
  cursor = cnx.cursor()
  cursor.execute("select uname,pass from user where uname ='" + sys.argv[2] + "'")  
  row = cursor.fetchone()
  if cursor.rowcount == 0:
    sys.exit('                                                                                        Username not registered')

  else:
    if row[1] == SHA256.new(sys.argv[3]).hexdigest():
      cnx = mysql.connector.connect(**config)
      cursor = cnx.cursor()
      cursor.execute("Select hashvalue,filename,digest from crypto where username='" + sys.argv[2] + "' and filename = '" + sys.argv[4] + "'")
      if cursor.rowcount != 0:
        row = cursor.fetchone()
        secret = 8 *'0\x00'
        decrypt = AES.new(row[0].decode("hex"), AES.MODE_CTR, counter=lambda: secret)
        f, metadata = client.get_file_and_metadata(row[2])
        out = open('downloads\\' + row[1], 'wb+')
        data = decrypt.decrypt(f.read())
        out.write(data)
        print ""
        print ""
        print '                                                                                        Downloaded: ' + row[1]
      else:
        print '                                                         File not found. Check if the file name is correct or if this file is uploaded or not.'
    else:
      print '                                                                                    Please enter the correct password.'
elif sys.argv[1] == "help" or sys.argv[1] == "Help" or sys.argv[1] == "?":
  print ''
  print "                                                     python cryptoX.py install - Installs CryptoX and equips it the with the initial components"
  print ''
  print "                                                     python cryptoX.py register <username> <password> - Registers a user with the given credentials"  
  print ''
  print '                                                     python cryptoX.py -u <username> <password> <filename> - Uploads the file that is given in the input'
  print ''
  print "                                                     python cryptoX.py -d <username> <password> <filename> - Downloads the file that is given in the input"
  print ''
  print "                                                     python cryptoX.py listfiles <username> <password> - Lists all the files uploaded by the used and those that someone has shared with him"
  print ''
  print "                                                     python cryptoX.py <username1> <password1> shareswith <username2> <filename> - Enables Username1 to share a file with Username2"
  print ''
  print "                                                     python cryptoX.py help - Prints the help manual for the CryptoX tool"

elif sys.argv[3] == "shareswith":
  sender = sys.argv[1]
  reciever = sys.argv[4]
  cursor = cnx.cursor()
  cursor2 = cnx.cursor()
  cursor.execute("select uname,pass from user where uname ='" + sender + "'")
  cursor2.execute("select uname from user where uname ='" + reciever + "'")  
  row = cursor.fetchone()
  row2 = cursor2.fetchone()

  if cursor.rowcount == 0:
    sys.exit('                                                                                    Sender\'s username not registered')
  if cursor2.rowcount == 0:
    sys.exit('                                                                                No such user registered to share the file')
  

  else:
    if row[1] == SHA256.new(sys.argv[2]).hexdigest():
      cursor.execute("select hashvalue,digest from crypto where username='" + sender + "' and filename='" + sys.argv[5] + "'")
      row = cursor.fetchone()      
      if cursor.rowcount == 0:
        print 'No such file is present'
      else:
        add_info = ("INSERT INTO sharedfiles (username, hashvalue, filename, digest, sentby) VALUES (%s, %s, %s, %s, %s)")
        data_info = (reciever,row[0],sys.argv[5], row[1], sender)
        cursor.execute(add_info, data_info)
        cnx.commit()
        print 'The file ' + sys.argv[5] + ' is successfully shared with ' + reciever
    else:
      print '                                                                          Password is incorrect. Please enter the valid password.'
elif sys.argv[1] == "listfiles":
  cursor = cnx.cursor()
  cursor2 = cnx.cursor()
  cursor.execute("select filename from crypto where username='" + sys.argv[2] + "'")
  cursor2.execute("select filename,sentby from sharedfiles where username='" + sys.argv[2] + "'")

  rows = cursor.fetchall()
  if rows:
    print '                                                                                     Uploaded Files:'
    for row in rows:    
      print '                                                                                   >' + row[0]

  rows2 = cursor2.fetchall()
  if rows2:
    print '                                                                                     Shared Files:'
    for row in rows2:
      print '                                                                                   >' + row[0] + ': Shared by ' + row[1]
  if not rows and not rows2:
    print '                                                                                              No files in the list'
else:
  print '                                                                                                  Invalid Parameter'

