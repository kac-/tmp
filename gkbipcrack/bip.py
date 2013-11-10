# -*- coding: utf-8 -*-
# Copyright (c) 2013 W.J. van der Laan
# parts sourced from jackjack's pywallet.py (https://github.com/jackjack-jj/pywallet)
# Distributed under the MIT/X11 software license

from bitcoin.base58 import CBase58Data
from binascii import b2a_hex, a2b_hex
import struct
import hashlib
import scrypt, random
from Crypto.Cipher import AES
import sys

# secp256k1
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

# python-ecdsa code (EC_KEY implementation)

class CurveFp( object ):
	def __init__( self, p, a, b ):
		self.__p = p
		self.__a = a
		self.__b = b

	def p( self ):
		return self.__p

	def a( self ):
		return self.__a

	def b( self ):
		return self.__b

	def contains_point( self, x, y ):
		return ( y * y - ( x * x * x + self.__a * x + self.__b ) ) % self.__p == 0

class Point( object ):
	def __init__( self, curve, x, y, order = None ):
		self.__curve = curve
		self.__x = x
		self.__y = y
		self.__order = order
		if self.__curve: assert self.__curve.contains_point( x, y )
		if order: assert self * order == INFINITY
 
	def __add__( self, other ):
		if other == INFINITY: return self
		if self == INFINITY: return other
		assert self.__curve == other.__curve
		if self.__x == other.__x:
			if ( self.__y + other.__y ) % self.__curve.p() == 0:
				return INFINITY
			else:
				return self.double()

		p = self.__curve.p()
		l = ( ( other.__y - self.__y ) * \
					inverse_mod( other.__x - self.__x, p ) ) % p
		x3 = ( l * l - self.__x - other.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def __mul__( self, other ):
		def leftmost_bit( x ):
			assert x > 0
			result = 1L
			while result <= x: result = 2 * result
			return result / 2

		e = other
		if self.__order: e = e % self.__order
		if e == 0: return INFINITY
		if self == INFINITY: return INFINITY
		assert e > 0
		e3 = 3 * e
		negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
		i = leftmost_bit( e3 ) / 2
		result = self
		while i > 1:
			result = result.double()
			if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
			if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
			i = i / 2
		return result

	def __rmul__( self, other ):
		return self * other

	def __str__( self ):
		if self == INFINITY: return "infinity"
		return "(%d,%d)" % ( self.__x, self.__y )

	def double( self ):
		if self == INFINITY:
			return INFINITY

		p = self.__curve.p()
		a = self.__curve.a()
		l = ( ( 3 * self.__x * self.__x + a ) * \
					inverse_mod( 2 * self.__y, p ) ) % p
		x3 = ( l * l - 2 * self.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def x( self ):
		return self.__x

	def y( self ):
		return self.__y

	def curve( self ):
		return self.__curve
	
	def order( self ):
		return self.__order
		
INFINITY = Point( None, None, None )

def inverse_mod( a, m ):
	if a < 0 or m <= a: a = a % m
	c, d = a, m
	uc, vc, ud, vd = 1, 0, 0, 1
	while c != 0:
		q, c, d = divmod( d, c ) + ( c, )
		uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
	assert d == 1
	if ud > 0: return ud
	else: return ud + m

class Signature( object ):
	def __init__( self, r, s ):
		self.r = r
		self.s = s
		
class Public_key( object ):
	def __init__( self, generator, point ):
		self.curve = generator.curve()
		self.generator = generator
		self.point = point
		n = generator.order()
		if not n:
			raise RuntimeError, "Generator point must have order."
		if not n * point == INFINITY:
			raise RuntimeError, "Generator point order is bad."
		if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
			raise RuntimeError, "Generator point has x or y out of range."

	def verifies( self, hash, signature ):
		G = self.generator
		n = G.order()
		r = signature.r
		s = signature.s
		if r < 1 or r > n-1: return False
		if s < 1 or s > n-1: return False
		c = inverse_mod( s, n )
		u1 = ( hash * c ) % n
		u2 = ( r * c ) % n
		xy = u1 * G + u2 * self.point
		v = xy.x() % n
		return v == r

class Private_key( object ):
	def __init__( self, public_key, secret_multiplier ):
		self.public_key = public_key
		self.secret_multiplier = secret_multiplier

	def der( self ):
		hex_der_key = '06052b8104000a30740201010420' + \
			'%064x' % self.secret_multiplier + \
			'a00706052b8104000aa14403420004' + \
			'%064x' % self.public_key.point.x() + \
			'%064x' % self.public_key.point.y()
		return hex_der_key.decode('hex')

	def sign( self, hash, random_k ):
		G = self.public_key.generator
		n = G.order()
		k = random_k % n
		p1 = k * G
		r = p1.x()
		if r == 0: raise RuntimeError, "amazingly unlucky random number r"
		s = ( inverse_mod( k, n ) * \
					( hash + ( self.secret_multiplier * r ) % n ) ) % n
		if s == 0: raise RuntimeError, "amazingly unlucky random number s"
		return Signature( r, s )

class EC_KEY(object):
	def __init__( self, secret ):
		curve = CurveFp( _p, _a, _b )
		generator = Point( curve, _Gx, _Gy, _r )
		self.pubkey = Public_key( generator, generator * secret )
		self.privkey = Private_key( self.pubkey, secret )
		self.secret = secret

# end of python-ecdsa code

# pywallet openssl private key implementation

def i2d_ECPrivateKey(pkey, compressed=False):#, crypted=True):
	part3='a081a53081a2020101302c06072a8648ce3d0101022100'  # for uncompressed keys
	if compressed:
		if True:#not crypted:  ## Bitcoin accepts both part3's for crypted wallets...
			part3='a08185308182020101302c06072a8648ce3d0101022100'  # for compressed keys
		key = '3081d30201010420' + \
			'%064x' % pkey.secret + \
			part3 + \
			'%064x' % _p + \
			'3006040100040107042102' + \
			'%064x' % _Gx + \
			'022100' + \
			'%064x' % _r + \
			'020101a124032200'
	else:
		key = '308201130201010420' + \
			'%064x' % pkey.secret + \
			part3 + \
			'%064x' % _p + \
			'3006040100040107044104' + \
			'%064x' % _Gx + \
			'%064x' % _Gy + \
			'022100' + \
			'%064x' % _r + \
			'020101a144034200'

	return key.decode('hex') + i2o_ECPublicKey(pkey, compressed)

def i2o_ECPublicKey(pkey, compressed=False):
	# public keys are 65 bytes long (520 bits)
	# 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
	# 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
	# compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
	if compressed:
		if pkey.pubkey.point.y() & 1:
			key = '03' + '%064x' % pkey.pubkey.point.x()
		else:
			key = '02' + '%064x' % pkey.pubkey.point.x()
	else:
		key = '04' + \
			'%064x' % pkey.pubkey.point.x() + \
			'%064x' % pkey.pubkey.point.y()

	return key.decode('hex')

# end secp256k1

def hash_160(public_key):
 	md = hashlib.new('ripemd160')
	md.update(hashlib.sha256(public_key).digest())
	return md.digest()

addrtype = 0
def public_key_to_bc_address(public_key, v=addrtype):
    h160 = hash_160(public_key)
    return str(CBase58Data(h160, v))

def double_sha256(x):
    x = hashlib.sha256(x).digest()
    x = hashlib.sha256(x).digest()
    return x

#pubkey = '1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2' # test vector
#pubkey = '1nsEdR3HqU6jaAPtqEwXRd9WFkrFzGn9r' #aąc
pubkey = '1KmMbhS2hSmLFDNXTYH3okE4k84gwZaiwV'
pubd = double_sha256(pubkey)

#privkey = '6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX' # test vector
#privkey = '6PfS9Qamt8GMLGgNCcnvban9SPzGTvCp9Xjhxdz6wVCV2wpGqkHtsSNr6N' #aąc
privkey = '6PfYU8C5sLGsjDNWsCHRYD6G5noFmc184Q4owtnfvXrUdpsfNkeTq2HDV8'
privkey = CBase58Data.from_str(privkey)

print 'key', b2a_hex(privkey)
print 'version', privkey.nVersion

assert(privkey[0] == '\x43')
print "EC multiplication is used"
assert(len(privkey) == 1+1+4+16+16)
flags = ord(privkey[1])
if flags & 0x20:
    use_compressed = True
    print "Should be compressed"
else:
    use_compressed = False
    print "Should not be compressed"
if flags & 0x04:
    lotsequence_present = True
    print "Lot and sequence number are encoded into the first factor"
else:
    lotsequence_present = False
    print "No lot and sequence number are encoded"
assert((flags & ~0xE4) == 0)
print

addresshash = privkey[2:2+4]
ownersalt = privkey[6:6+4]
lotsequence = privkey[10:10+4]
ownerentropy = ownersalt + lotsequence
encryptedpart1 = privkey[14:14+8]
encryptedpart2 = privkey[22:22+16]

print 'addresshash', b2a_hex(addresshash), b2a_hex(pubd[0:4])
print 'ownersalt', b2a_hex(ownersalt)
print 'lotsequence', b2a_hex(lotsequence)
print 'ownerentropy', b2a_hex(ownerentropy)
print 'encryptedpart1', b2a_hex(encryptedpart1)
print 'encryptedpart2', b2a_hex(encryptedpart2)


curve = CurveFp( _p, _a, _b )
generator = Point( curve, _Gx, _Gy, _r )

def encode_point(point, compressed=False):
    '''Encode a point in public key notation'''
    # public keys are 65 bytes long (520 bits)
    # 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
    # 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
    # compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    if compressed:
        if point.y() & 1:
            key = '03' + '%064x' % point.x()
        else:
            key = '02' + '%064x' % point.x()
    else:
        key = '04' + \
                '%064x' % point.x() + \
                '%064x' % point.y()
    return a2b_hex(key)

def bin_to_uint256(x):
    return int(b2a_hex(x), 16)

def test(passphrase):
    print '---- passphrase (hex) ', b2a_hex(passphrase)
    # 2. Derive passfactor using scrypt with ownersalt and the user's passphrase and use it to recompute passpoint
    if lotsequence_present:
        salt = ownersalt
    else:
        salt = ownerentropy
    prefactor = scrypt.hash(passphrase, salt, N=16384, r=8, p=8, buflen=32)
    if lotsequence_present:
        passfactor = double_sha256(prefactor + ownerentropy)
    else:
        passfactor = prefactor
    assert(len(passfactor) == 32)
    print 'passfactor', b2a_hex(passfactor)

    passfactor_i = bin_to_uint256(passfactor)
    passpoint_p = generator * passfactor_i
    passpoint = encode_point(passpoint_p, compressed=True)
    assert(len(passpoint) == 33)
    print 'passpoint', b2a_hex(passpoint)

    # 3. Derive decryption key for seedb using scrypt with passpoint, addresshash, and ownersalt
    seedb_decrypt_key = scrypt.hash(passpoint, addresshash + ownerentropy, N=1024, r=1, p=1, buflen=64)
    print 'seedb_decrypt_key', b2a_hex(seedb_decrypt_key)

    derivedhalf1 = seedb_decrypt_key[0:32]
    derivedhalf2 = seedb_decrypt_key[32:64]

    # 4. Decrypt encryptedpart2 using AES256Decrypt to yield the last 8 bytes of seedb and the last 8 bytes of encryptedpart1.
    aes = AES.new(derivedhalf2, AES.MODE_ECB)
    decryptedpart2 = aes.decrypt(encryptedpart2)
    print 'decryptedpart2', b2a_hex(decryptedpart2)

    # decryptedpart2 is (encryptedpart1[8...15] + seedb[16...23]) xor derivedhalf1[16...31] 
    es = ''
    for x in xrange(16):
        es += chr(ord(decryptedpart2[x]) ^ ord(derivedhalf1[16+x]))
    # es is encryptedpart1[8...15] + seedb[16...23]
    encryptedpart1_full = encryptedpart1 + es[0:8]
    assert(len(encryptedpart1_full) == 16)

    # 5. Decrypt encryptedpart1 to yield the remainder of seedb
    # decryptedpart1 is seedb[0...15]] xor derivedhalf1[0...15]
    decryptedpart1 = aes.decrypt(encryptedpart1_full)

    # recover seedb
    seedb = ''
    for x in xrange(16):
        seedb += chr(ord(decryptedpart1[x]) ^ ord(derivedhalf1[0+x]))
    seedb += es[8:16]
    assert(len(seedb) == 24)

    # 6. Use seedb to compute factorb
    factorb = bin_to_uint256(double_sha256(seedb))

    # 7. Multiply passfactor by factorb mod N to yield the private key associated with generatedaddress.
    secret = (passfactor_i * factorb) % _r

    # 8. Convert that private key into a Bitcoin address, honoring the compression preference specified in the encrypted key.
    pubkey = Public_key(generator, generator * secret)
    pubkey_encoded = encode_point(pubkey.point, use_compressed)
    addr = public_key_to_bc_address(pubkey_encoded)

    print "Recovered address", addr

    # 9. Hash the Bitcoin address, and verify that addresshash from the encrypted private key record matches the hash. If not, report that the passphrase entry was incorrect.
    validation = double_sha256(addr)[0:4]
    print 'addresshash', b2a_hex(addresshash), b2a_hex(validation)
    if addresshash == validation:
        print 'match!'
        return 1
    return 0

#test('TestingOneTwoThree')
#exit(0)

# startval and endval can be customized for process paralellism
# XXX currently covers ASCII only, is this enough?


