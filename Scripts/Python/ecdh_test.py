from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pythonSC as pcsc

readers_list = ['Virtual PCD 00 00']

def trn(cmd, expsw = 0, expdata = None, descr = ''):
	if (isinstance(cmd, str)):
		cmd = pcsc.asciiToHex(cmd)
	rsp = pcsc.transmit(card, protocol, cmd, descr)
	if (expdata != None):
		if (isinstance(expdata, str)):
			expdata = pcsc.asciiToHex(expdata)
		assert(rsp[:-2] == expdata)
	if (expsw != 0):
		assert((rsp[-2] << 8) + rsp[-1] == expsw)
	return rsp


def hexToAscii(ar):
	rst = ''
	for a in ar:
		rst += "{:02x}".format(a)
	return rst


def ln(array):
	if (isinstance(array, str)):
		array = pcsc.asciiToHex(array)
	return [len(array)] + array


def uncompress(public_key):
	ret_val = hex(public_key.public_numbers().x)[2:] + hex(public_key.public_numbers().y)[2:]
	ret_val_len = ln(ret_val)[0]
	
	# padd the leading zero for the MSB (if required)
	if ret_val_len == 63:
		ret_val = '0' + ret_val
	elif ret_val_len == 62:
		ret_val = '00' + ret_val
	return '04' + ret_val


class DiffHell:
	def __init__(self):
		# of type EllipticCurvePrivateKey
		self.priv_key = ec.generate_private_key(ec.SECP256K1())
		self.publ_key = self.priv_key.public_key()
		self.cipher = None
		self.secret_key = None
		self.iv = bytearray(16)

	def gen_shared(self, public_key):
		shared_key = self.priv_key.exchange(ec.ECDH(), public_key)
		return shared_key
	
	def init_cipher(self, sk):
		self.secret_key = sk
		# print("Host secret key: ", self.secret_key)
		self.cipher = Cipher(algorithms.AES(sk), modes.CBC(self.iv))
	
	def encrypt_msg(self, plain_text: bytes):
		encryptor = self.cipher.encryptor()
		cipher_text = encryptor.update(plain_text) + encryptor.finalize()
		return cipher_text

	def decrypt_msg(self, cipher_bytes):
		decryptor = self.cipher.decryptor()
		plain_text = decryptor.update(cipher_bytes) + decryptor.finalize()
		return plain_text


def main_func():

	global context
	global card
	global protocol
	dh = DiffHell()

	context, card, protocol = pcsc.openCardAnyReader(readers_list)

	trn(           pcsc.asciiToHex('00A40400') + ln('A00000000101'),          expsw = 0x9000, descr = 'Select CryptoKey')
	trn(           pcsc.asciiToHex('00200000') + ln('3131313131'),            expsw = 0x9000, descr = 'Verify PIN')
	response = trn(pcsc.asciiToHex('00220000') + ln(uncompress(dh.publ_key)), expsw = 0x9000, descr = 'OPEN SM: get public key')

	_x = int.from_bytes(response[1:33], 'big')
	_y = int.from_bytes(response[33:65], 'big')

	card_publ_key = ec.EllipticCurvePublicNumbers(_x, _y, ec.SECP256K1())

	host_shared = dh.gen_shared(card_publ_key.public_key())
	print("\nHost shared key: ", hexToAscii(host_shared))
	print("\nCard shared key: ", hexToAscii(response[65:97]))

	# dh.init_cipher(host_shared[0:16])

	# response      = trn(pcsc.asciiToHex('0022010000'), expsw = 0x9000, descr = 'OPEN SM: get a random')
	# cipher_text   = dh.encrypt_msg(bytes(response[:-2]))
	# # print("\nHost cipher text: ", hexToAscii(cipher_text))

	# response = trn(pcsc.asciiToHex('00220200') + ln(hexToAscii(cipher_text)), expsw = 0x9000, descr = 'OPEN SM: check the cryptogram')

	pcsc.disconnect(card)

main_func()