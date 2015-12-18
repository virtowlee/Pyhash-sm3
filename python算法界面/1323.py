from Tkinter import *
import ttk
import linecache
import hmac
import binascii
from  hashlib import *
from openssl_wrapper import OpenSSL
from struct import pack, unpack
import struct

gui=Tk()
gui.title("My First Work")
gui.geometry("1000x900")
n=ttk.Notebook(gui)
n.pack(side=LEFT)
lee = ttk.Frame(n)   #第一个窗口
Label(lee,text="ECC",font=("Aerial",30)).pack()
#1第一部分
frm1=Frame(lee)
Label(frm1,text="content",font=("Aerial",30)).pack(side=LEFT)
ssl=StringVar()
ok=Entry(frm1,textvariable=ssl)
ok.pack(expand=400,fill="both",ipadx=250,ipady=30)
#2第二部分
frm2=Frame(lee)
Label(frm2,text="(A&B)key",font=("Aerial",30)).pack(side=LEFT)
lop=StringVar()
my=Entry(frm2,textvariable=lop)
my.pack(ipadx=240,ipady=15)
vcc=StringVar()
vcm=Entry(frm2,textvariable=vcc)
vcm.pack(ipadx=240,ipady=15)
pol=StringVar()
pkl=Entry(frm2,textvariable=pol)
pkl.pack(ipadx=240,ipady=15)
qwe=StringVar()
wer=Entry(frm2,textvariable=qwe)
wer.pack(ipadx=240,ipady=15)

#自我定义函数
def printzhi():
    f=open("content.txt","r")
    for line in f.readlines()[1:2]:
        wawak=line.strip("\n")
    ssl.set(wawak)
def printkai():
    #1. Generate a ephemeral EC key pair
# we use shortand patent free EC curve in the QR scenerio, which is 'secp160r1'
#PUBKEY='02c500146ec52c4fdae22c1c18d81b3679cf70397fdaab8f0014bac0efaff80ce2ec719ba1bcaa53530bf03d6d95'
#PRIVKEY='l1s331231'#'02c500147bd49a3ea78ba2d5a06920f4326e693002419685'
#PUBKEY=PUBKEY.decode('hex')
#PRIVKEY=PRIVKEY.decode('hex')

    def gen_ec_keypair(curve='secp112r1'):
    #this function generates EC key pair
        try:
            curve=OpenSSL.curves[curve]
            key = OpenSSL.EC_KEY_new_by_curve_name(curve)	
            OpenSSL.EC_KEY_generate_key(key)
            _pubkey_x = OpenSSL.BN_new()
            _pubkey_y = OpenSSL.BN_new()
            _privkey = OpenSSL.EC_KEY_get0_private_key(key)
            _pubkey = OpenSSL.EC_KEY_get0_public_key(key)
            _group = OpenSSL.EC_KEY_get0_group(key)
            OpenSSL.EC_POINT_get_affine_coordinates_GFp(_group, _pubkey, _pubkey_x, _pubkey_y, 0)
    
            privkey = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(_privkey))
            pubkeyx = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(_pubkey_x))
            pubkeyy = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(_pubkey_y))
            OpenSSL.BN_bn2bin(_privkey, privkey)
            privkey = privkey.raw
            OpenSSL.BN_bn2bin(_pubkey_x, pubkeyx)
            pubkeyx = pubkeyx.raw
            OpenSSL.BN_bn2bin(_pubkey_y, pubkeyy)
            pubkeyy = pubkeyy.raw
        #self.raw_check_key(privkey, pubkeyx, pubkeyy)

            full_privkey=pack('!H', curve) + pack('!H', len(privkey)) + privkey
            full_pubkey=pack('!H', curve) + pack('!H', len(pubkeyx)) + pubkeyx + pack('!H', len(pubkeyy)) + pubkeyy
            return full_privkey, full_pubkey

        finally:
        #release c pointers
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(_pubkey_x)
            OpenSSL.BN_free(_pubkey_y)

    def ecdh_key(a_privkey, b_pubkey):
    #keys should be in binary format
        a_curve=int(a_privkey[0:2].encode('hex'), 16)
        b_curve=int(b_pubkey[0:2].encode('hex'), 16)
        if a_curve != b_curve:
            raise Exception("ECDH Error: Both key must have the save curve type.")
    
        sx=int(b_pubkey[2:4].encode('hex'), 16)
        sy=int(b_pubkey[4+sx:sx+6].encode('hex'), 16)
        pub_x, pub_y = b_pubkey[4:4+sx], b_pubkey[6+sx:6+sx+sy]

        b_key=OpenSSL.EC_KEY_new_by_curve_name(b_curve)
        _pub_x=OpenSSL.BN_bin2bn(pub_x, sx, 0)
        _pub_y=OpenSSL.BN_bin2bn(pub_y, sy, 0)
        _group=OpenSSL.EC_KEY_get0_group(b_key)
        _pubkey=OpenSSL.EC_POINT_new(_group)
        OpenSSL.EC_POINT_set_affine_coordinates_GFp(_group, _pubkey, _pub_x, _pub_y, 0)
        OpenSSL.EC_KEY_set_public_key(b_key, _pubkey)
    #OpenSSL.EC_KEY_check_key(b_key)
    
        s=int(a_privkey[2:4].encode('hex'), 16)
        priv=a_privkey[4:4+s]
        a_key=OpenSSL.EC_KEY_new_by_curve_name(a_curve)
        _privkey=OpenSSL.BN_bin2bn(priv, len(priv), 0)
        OpenSSL.EC_KEY_set_private_key(a_key, _privkey)
    
    #ECDH
        OpenSSL.ECDH_set_method(a_key, OpenSSL.ECDH_OpenSSL())
        ecdh_buf = OpenSSL.malloc(0, s) #computed buffer size should the same as key length
        ecdh_keylen=OpenSSL.ECDH_compute_key(ecdh_buf, s, _pubkey, a_key, 0)
        return ecdh_buf.raw


    from Crypto.Cipher import AES

    def encrypt(a_privkey, a_pubkey, b_pubkey, content):
        ecdh1=ecdh_key(a_privkey,b_pubkey)
        shared_key=md5(ecdh1).digest()   #we need 128 bit key in our QR scenerio
        obj = AES.new(shared_key, AES.MODE_ECB)
        ciphertext = obj.encrypt(content)
        qr=(a_pubkey+ciphertext).encode('base64')
        return qr

    def decrypt(b_privkey, qr):
        qr=qr.decode('base64')
        sx=int(qr[2:4].encode('hex'), 16)
        sy=int(qr[4+sx:sx+6].encode('hex'), 16)
        a_pubkey=qr[:6+sx+sy]
        ciphertext=qr[6+sx+sy:]
        ecdh2=ecdh_key(b_privkey,a_pubkey)
        shared_key=md5(ecdh2).digest()
        obj = AES.new(shared_key, AES.MODE_ECB)
        content = obj.decrypt(ciphertext)
        return content


    a= gen_ec_keypair('secp112r2') #a key is ephemeral, generated everytime
    b=gen_ec_keypair('secp112r2')  #in real code, this key pair should come from server, and a client has its public key only

    efg= a[0].encode('hex')
    wsd='Public:' + a[1].encode('hex')
  #'Alice -> Private:'+ a[0].encode('hex'), 'Public:' + a[1].encode('hex')
    ijn= b[0].encode('hex')
    oie='Public:' + b[1].encode('hex')

#'Bob -> Private:' + b[0].encode('hex'), 'Public:' + b[1].encode('hex')

    e1= ecdh_key(a[0],b[1])
    e2=ecdh_key(b[0],a[1])   #e2 is for server code only

    iui=e1.encode('hex')
#e2.encode('hex')
    f=open("content.txt","r")
    for line in f.readlines()[1:2]:
        wsad=line.strip("\n")
    bm=buffer(wsad)        #must 16 letter
    qr= encrypt(a[0],a[1],b[1],bm)
    poa=len(qr)
    popo=": "
    polop=qr
    
#import qrcode
#qrcode.make(qr).show()


#server does the following:
    content=decrypt(b[0], qr)
    print 'After decryption, content is ', content
    sd="Alice(PRI):  "
    sd=sd+efg
    lop.set(sd)
    sf="Alice(PUB):  "
    sf=sf+wsd
    vcc.set(sf)
    sw="Bob(PRI):     "
    sw=sw+ijn
    pol.set(sw)
    sr="Bob(PUB):    "
    sr=sr+oie
    qwe.set(sr)
    sg="QR code:  "
    sg=sg+popo+polop
    kal.set(sg)
    cio="ECDH CODE:  "
    cio=cio+iui
    ghg.set(cio)
#3第三部分
frm3=Frame(lee)
Label(frm3,text="Code",font=("Aerial",30)).pack(side=LEFT)
kal=StringVar()
zhi=Entry(frm3,textvariable=kal)
zhi.pack(ipadx=295,ipady=30)
ghg=StringVar()
ghh=Entry(frm3,textvariable=ghg)
ghh.pack(ipadx=290,ipady=30)
    
#按钮1
b1=Button(lee,text="Content",width=10,height=2,bg="green",command=printzhi)#未定义按钮

#按钮2
b2=Button(lee,text="ECC",width=10,height=2,bg="blue",command=printkai)


b1.pack(side=TOP)
frm1.pack(side=TOP)
b2.pack(side=TOP)
frm2.pack(side=TOP)

frm3.pack(side=TOP)




f2=ttk.Frame(n)  #第二个窗口
Label(f2,text="HMAC",font=("Aerial",30)).pack()


#自我定义函数
def printzhi():
    f=open("test.txt","r")
    for line in f.readlines()[3:4]:
        y=line.strip("\n")
    var.set(y)
    op=binascii.b2a_hex(y.encode("gbk"))
    wow.set(op)
def printkai():
    f=open ("test.txt","r")
    for line in f.readlines()[1:2]:
        t=line.strip("\n")
    var1.set(t)
    ol=binascii.b2a_hex(t.encode("gbk"))
    lol.set(ol)
def pringtbao():
    f=open("test.txt","r")
    for line in f.readlines()[3:4]:
        y=line.strip("\n")
    f=open ("test.txt","r")
    for line in f.readlines()[1:2]:
        t=line.strip("\n")
    t1=t
    y1=y
    hm=hmac.new(t1)
    hm.update(y1)
    ce=hm.hexdigest()
    cc="MD5 is :   "
    cc=cc+ce
    mm.set(cc)   #MD5

    hm1=hmac.new(t1,y1,sha1).hexdigest()
    cs="SHA is :   "
    cs=cs+hm1
    sh.set(cs)  #SHA1

    hm2=hmac.new(t1,y1,sha256).hexdigest()
    ca="SHA256 is  "
    ca=ca+hm2
    ha.set(ca)  #SHA256

    hm3=hmac.new(t1,y1,sha384).hexdigest()
    cd="SHA384 is    "
    cd=cd+hm3
    ha3.set(cd)  #SHA384

    hm4=hmac.new(t1,y1,sha512).hexdigest()
    cf="SHA512 is    "
    cf=cf+hm4
    ha4.set(cf)



#1第一部分
frm1=Frame(f2)
Label(frm1,text="MESSAGE",font=("Aerial",30)).pack(side=LEFT)
var=StringVar()
ok=Entry(frm1,textvariable=var)
ok.pack(expand=400,fill="both",ipadx=250,ipady=30)
wow=StringVar()
wow1=Entry(frm1,textvariable=wow)
wow1.pack(ipadx=250,ipady=20)
#2第二部分
frm2=Frame(f2)
Label(frm2,text="key",font=("Aerial",30)).pack(side=LEFT)
var1=StringVar()
my=Entry(frm2,textvariable=var1)
my.pack(ipadx=250,ipady=30)
lol=StringVar()
lola=Entry(frm2,textvariable=lol)
lola.pack(ipadx=250,ipady=20)

#3第三部分
frm3=Frame(f2)
Label(frm3,text="HMAC",font=("Aerial",30)).pack(side=LEFT)
mm=StringVar()#MD5方框
zhi=Entry(frm3,textvariable=mm)
zhi.pack(ipadx=295,ipady=10)

sh=StringVar()#SHA1方框
sha=Entry(frm3,textvariable=sh)
sha.pack(ipadx=295,ipady=10)

ha=StringVar()#SHA256值
ha2=Entry(frm3,textvariable=ha)
ha2.pack(ipadx=295,ipady=10)

ha3=StringVar()   #SHA384值
haa=Entry(frm3,textvariable=ha3)
haa.pack(ipadx=295,ipady=10)

ha4=StringVar()
has=Entry(frm3,textvariable=ha4)
has.pack(ipadx=295,ipady=10)



    
#按钮1
b1=Button(f2,text="MESSAGE",width=10,height=2,bg="Yellow",command=printzhi)#未定义按钮

#按钮2
b2=Button(f2,text="KEY",width=10,height=2,bg="blue",command=printkai)

#按钮3
b3=Button(f2,text="HMAC",width=10,height=2,bg="red",command=pringtbao)


b1.pack(side=TOP)
frm1.pack(side=TOP)
b2.pack(side=TOP)
frm2.pack(side=TOP)
b3.pack(side=TOP)
frm3.pack(side=TOP)


polo=ttk.Frame(n)  #第三个窗口
Label(polo,text="SM3",font=("Aerial",30)).pack()
cff=Frame(polo)  #矩形区域
cee=Text(cff,height=10,width=50)
def smsm():  #明文读取框
    f=open("bkbk.txt","r")
    for line in f.readlines()[1:2]:
        y=line.strip("\n")
        cee.insert(INSERT,y)
c1=Button(polo,text="MESSAGE",width=8,height=2,command=smsm)  #明文导入按钮
c1.pack(side=TOP)
cee.pack(side=TOP)
cff.pack(side=TOP)


cgg=Frame(polo)  #第二个矩形区域
chh=Text(cgg,height=10,width=50)
#chh=StringVar()

def hkhk():
    IV="7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e"  #初始值
    IV = int(IV.replace(" ", ""), 16)
    a = []
    for i in range(0, 8):
        a.append(0)
        a[i] = (IV >> ((7 - i) * 32)) & 0xFFFFFFFF
    IV = a
    list33=[]
    def out_hex(list1):
        for i in list1:
            list33.append( "%08x" % i)
        print "\n",

    def rotate_left(a, k):
        k = k % 32
        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))

    T_j = []
    for i in range(0, 16):
        T_j.append(0)
        T_j[i] = 0x79cc4519
    for i in range(16, 64):
        T_j.append(0)
        T_j[i] = 0x7a879d8a

    def FF_j(X, Y, Z, j):
        if 0 <= j and j < 16:
            ret = X ^ Y ^ Z
        elif 16 <= j and j < 64:
            ret = (X & Y) | (X & Z) | (Y & Z)
        return ret

    def GG_j(X, Y, Z, j):
        if 0 <= j and j < 16:
            ret = X ^ Y ^ Z
        elif 16 <= j and j < 64:
            #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
            ret = (X & Y) | ((~ X) & Z)
        return ret

    def P_0(X):
        return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17))

    def P_1(X):
        return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23))

    def CF(V_i, B_i):
        W = []
        for j in range(0, 16):
            W.append(0)
            unpack_list = struct.unpack(">I", B_i[j*4:(j+1)*4])
            W[j] = unpack_list[0]
        for j in range(16, 68):
            W.append(0)
            W[j] = P_1(W[j-16] ^ W[j-9] ^ (rotate_left(W[j-3], 15))) ^ (rotate_left(W[j-13], 7)) ^ W[j-6]
            str1 = "%08x" % W[j]
        W_1 = []
        for j in range(0, 64):
            W_1.append(0)
            W_1[j] = W[j] ^ W[j+4]
            str1 = "%08x" % W_1[j]

        A, B, C, D, E, F, G, H = V_i
        """
        print "00",
        out_hex([A, B, C, D, E, F, G, H])
        """
        for j in range(0, 64):
            SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ (rotate_left(A, 12))
            TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
            TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = rotate_left(B, 9)
            B = A
            A = TT1
            H = G
            G = rotate_left(F, 19)
            F = E
            E = P_0(TT2)

            A = A & 0xFFFFFFFF
            B = B & 0xFFFFFFFF
            C = C & 0xFFFFFFFF
            D = D & 0xFFFFFFFF
            E = E & 0xFFFFFFFF
            F = F & 0xFFFFFFFF
            G = G & 0xFFFFFFFF
            H = H & 0xFFFFFFFF
            """
            str1 = "%02d" % j
            if str1[0] == "0":
                str1 = ' ' + str1[1:]
            print str1,
            out_hex([A, B, C, D, E, F, G, H])
            """

        V_i_1 = []
        V_i_1.append(A ^ V_i[0])
        V_i_1.append(B ^ V_i[1])
        V_i_1.append(C ^ V_i[2])
        V_i_1.append(D ^ V_i[3])
        V_i_1.append(E ^ V_i[4])
        V_i_1.append(F ^ V_i[5])
        V_i_1.append(G ^ V_i[6])
        V_i_1.append(H ^ V_i[7])
        return V_i_1

    def hash_msg(msg):
        len1 = len(msg)
        reserve1 = len1 % 64
        msg = msg + chr(0x80)
        reserve1 = reserve1 + 1
        # 56-64, add 64 byte
        range_end = 56
        if reserve1 > range_end:
            range_end = range_end + 64
        for i in range(reserve1, range_end):
            msg = msg + chr(0x00)

        bit_length = (len1) * 8
        bit_length_string = struct.pack(">Q", bit_length)
        msg = msg + bit_length_string

        #print len(msg)
        group_count = len(msg) / 64

        m_1 = B = []
        for i in range(0, group_count):
            B.append(0)
            B[i] = msg[i*64:(i+1)*64]

        V = []
        V.append(0)
        V[0] = IV
        for i in range(0, group_count):
            V.append(0)
            V[i+1] = CF(V[i], B[i])

        return V[i+1]

    ts= hash_msg("abc")
    asdd=out_hex(ts)
    scc=" ".join(list33)
    chh.insert(END,scc)
    #chh.set(list33)
#chgg=Entry(cgg,textvariable=chh)
#chgg.pack(side=TOP)

c2=Button(polo,text="hash_Value",width=8,height=2,command=hkhk)   #杂凑值计算得出结果
c2.pack(side=TOP)
chh.pack(side=TOP)
cgg.pack(side=TOP)






n.add(lee, text='ECC')
n.add(f2, text='HMAC')
n.add(polo,text="SM3")


gui.mainloop()
