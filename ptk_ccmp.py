#coding:utf-8
"""
1.产生psk(personal模式下，PSK就是PMK)
PSK=PBKDF2(PassPhrase,ssid,4096,256)
2.产生PTK
PTK=PRF(PMK+ANonce+Snonce+AA+SPA)
PTK:前16字节算MIC
step_1:
000030002f4000a0200800a0200800a0200800000000000073ddfa0a000000001002940
9a000e1000000d800dc01df0288023a01e0191df3b1f0b0411d0d21dcb0411d0d21dc00
000700aaaa03000000888e0203005f02008a001000000000000000010e9be235c39ed6f
eb423f37cc5226a50ee97aff5e62a99d362fe70de76bde0f30000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000000
0000000ab7309f4

step_2:
000030002f4000a0200800a0200800a020080000000000002c06fb0a0000000010029409
a000d5000000d100d001d10288013a01b0411d0d21dce0191df3b1f0b0411d0d21dc0000
0000aaaa03000000888e0103007502010a0000000000000000000141394ef3e96420ddba
8604dae71e6f43b3b40a684e265eb0d714b11e8b13dcd400000000000000000000000000
000000000000000000000000000000000000004473835fc0e0a77eb34dfdf04313d71900
1630140100000fac040100000fac040100000fac020000106ca484
"""
"""
使用ccmp
"""
from pbkdf2 import *
import hmac
import hashlib
from struct import Struct
from operator import xor
from itertools import izip, starmap
import hmac,hashlib,binascii
from binascii import a2b_hex
from binascii import b2a_hex
_pack_int = Struct('>I').pack
PassPhrase="zerotech"
ssid="Dobby-0d21dc"
A = "Pairwise key expansion\0"
APMAC=a2b_hex("b0411d0d21dc")
ClientMAC=a2b_hex("e0191df3b1f0")
ANonce=a2b_hex("0e9be235c39ed6feb423f37cc5226a50ee97aff5e62a99d362fe70de76bde0f3")
Snonce=a2b_hex("41394ef3e96420ddba8604dae71e6f43b3b40a684e265eb0d714b11e8b13dcd4")
def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).encode('hex')


def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(data, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = starmap(xor, izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]

def PRF512(pmk,A,B):
    ptk1=hmac.new(pmk,binascii.a2b_qp(A)+B+chr(0),hashlib.sha1).digest()
    ptk2 = hmac.new(pmk, binascii.a2b_qp(A) + B + chr(1), hashlib.sha1).digest()
    ptk3 = hmac.new(pmk, binascii.a2b_qp(A) + B + chr(2), hashlib.sha1).digest()
    ptk4 = hmac.new(pmk, binascii.a2b_qp(A) + B + chr(3), hashlib.sha1).digest()
    return ptk1+ptk2+ptk3+ptk4[0:4]

def getPsk(PassPhrase,ssid):
    """
    计算psk的函数,返回的是assic码,personal模式下,psk==pmk,这里都用的是assic码形式
    """
    return pbkdf2_hex(PassPhrase,ssid,4096,256)[:64]

def getPtk(psk,APMAC,ClientMAC,ANonce,Snonce):
    """
    计算ptk的函数,返回ａssic码形式，传递进来的参数都是assic形式
    """
    pmk=a2b_hex(psk)
    A="Pairwise key expansion\0"
    B=min(APMAC,ClientMAC)+max(APMAC,ClientMAC)+min(ANonce,Snonce)+max(ANonce,Snonce)
    return b2a_hex(PRF512(pmk,A,B))

def getEncryKey(ptk):
    ptk=a2b_hex(ptk)
    return b2a_hex(ptk[32:48])
    
    
def check_sum(s):
    """
    计算UDP的校验和
    """
    s=str(s)
    if s.__len__()%4 !=0:
        s=s+'00'
    lens=s.__len__()
    alldata=[]
    for i in range(0,lens,4):
        alldata.append(int(s[i:i+4],16))
    sum_result=0
    for single_value in alldata:
        sum_result=sum_result+single_value

    hex_sum_result=str(hex(sum_result))[2:]
    len_hex_sum=len(hex_sum_result)
    if len_hex_sum>4:
        first_part=int(hex_sum_result[:len_hex_sum-4],16)
        second_part=int(hex_sum_result[len_hex_sum-4:],16)
        sum=hex(first_part+second_part)
        last_check_sum=hex(0xffff-int(sum[2:],16))[2:]
        return last_check_sum
    else:
        last_check_sum=hex(0xffff-int(hex_sum_result[2:],16))[2:]
        return last_check_sum

def crc32(v):
    """
    CRC校验
    """
    v=v.decode('hex')
    temp='%x' % (binascii.crc32(v) & 0xffffffff)
    if temp.__len__()!=8:
        temp='0'+temp
    s4=temp[0:2]
    s3=temp[2:4]
    s2=temp[4:6]
    s1=temp[6:8]
    return s1+s2+s3+s4　#这里注意字节序的问题

def udp_check():
    fake_header = 'c0a82a53c0a82a010011002b'  # srcip_4/dstip_4/00/11/len_2(udpheader+data)
    udp_header = '881dd431002b0000'  # srcport_2/dstport_2/len_2/0000
    data = '02016b0f000000f10000004cafb525020a8714000000010002000000000000c597db86'
    print hex(len(udp_header+data)/2)
    print check_sum(fake_header+udp_header+data)

if __name__ == '__main__':
    psk=getPsk(PassPhrase,ssid)
    print psk
    ptk=getPtk(psk,APMAC,ClientMAC,ANonce,Snonce)
    print ptk
    ptk=a2b_hex(ptk)
    data = a2b_hex("0103007502010a0000000000000000000141394ef3e96420ddba8604dae71e6f43b3b40a"
                   "684e265eb0d714b11e8b13dcd40000000000000000000000000000000000000000000000"
                   "00000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000")

    print "MIC      :4473835fc0e0a77eb34dfdf04313d719"
    print "calc MIC :" + (hmac.new(ptk[0:16], data, hashlib.sha1)).hexdigest()[0:32]

    print "Encry key:"+getEncryKey(b2a_hex(ptk))










