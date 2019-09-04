#!/usr/bin/python
# for my education, following along with bitcoins the hard way blog post:
# http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
import random
import hashlib
import ecdsa
import struct

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(n):
  result = ''
  while n > 0:
    result = b58[n%58] + result
    n /= 58
  return result

def base58decode(s):
  result = 0
  for i in range(0, len(s)):
    result = result * 58 + b58.index(s[i])
  return result

def base256encode(n):
  result = ''
  while n > 0:
    result = chr(n % 256) + result
    n /= 256
  return result

def base256decode(s):
  result = 0
  for c in s:
    result = result * 256 + ord(c)
  return result

def countLeadingChars(s, ch):
  count = 0
  for c in s:
    if c == ch:
      count += 1
    else:
      break
  return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
  s = chr(version) + payload
  checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
  result = s + checksum
  leadingZeros = countLeadingChars(result, '\0')
  return '1' * leadingZeros + base58encode(base256decode(result))


def base58CheckDecode(s):
  leadingOnes = countLeadingChars(s, '1')
  s = base256encode(base58decode(s))
  result = '\0' * leadingOnes + s[:-4]
  chk = s[-4:]
  checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
  assert(chk == checksum)
  version = result[0]
  return result[1:]

def privateKeyToWif(key_hex, compressed=False):
  if compressed: 
    key_hex=key_hex+'01'
#TDCoin
  return base58CheckEncode(0x6B, key_hex.decode('hex'))


def privateKeyToPublicKey(s, compressed=False):

  sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
  vk = sk.verifying_key

  if compressed:
    from ecdsa.util import number_to_string
    order = vk.pubkey.order
    # print "order", order
    x_str = number_to_string(vk.pubkey.point.x(), order).encode('hex')
    # print "x_str", x_str 
    sign = '02' if vk.pubkey.point.y() % 2 == 0 else '03'
    # print "sign", sign 
    return (sign+x_str)
  else:
    return ('\04' + vk.to_string()).encode('hex')


def pubKeyToAddr(s):
  ripemd160 = hashlib.new('ripemd160')
  ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
#TDCoin
  return base58CheckEncode(0x41, ripemd160.digest())

def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
  def makeOutput(data):
    redemptionSatoshis, outputScript = data
    return (struct.pack("<Q", redemptionSatoshis).encode('hex') +
           '%02x' % len(outputScript.decode('hex')) + outputScript)
  formattedOutputs = ''.join(map(makeOutput, outputs))
  return (
    "01000000" + # 4 bytes version
    "01" + # variant for number of inputs
    outputTransactionHash.decode('hex')[::-1].encode('hex') + # reverse OutputTransactionHash
    struct.pack('<L', sourceIndex).encode('hex') +
    '%02x' % len(scriptSig.decode('hex')) + scriptSig +
    "ffffffff" + # sequence
    "%02x" % len(outputs) + # number of outputs
    formattedOutputs +
    "00000000" # lockTime
  )


import sys
private_key = None
if len(sys.argv)>1:
  if sys.argv[1] == "-x":
    private_key = sys.argv[2].zfill(64)
  else:
    private_key = '%064x' % int(sys.argv[1])
else: private_key = ''.join(['%x' % random.randrange(16) for x in range(0,64)])

print "A private key: ", private_key
print "The uncompressed WIF: ",privateKeyToWif(private_key)
print "The WIF: ",privateKeyToWif(private_key, compressed=True)
public_key = privateKeyToPublicKey(private_key)
cpublic_key = privateKeyToPublicKey(private_key,compressed=True)
print "The uncompressed bitcoin pubkey: ", public_key
print "The tdcoin pubkey: ", cpublic_key
print "The uncompressed tdcoin address: ", pubKeyToAddr(public_key)
print "The tdcoin address: ", pubKeyToAddr(cpublic_key)
