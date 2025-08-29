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
	if ret_val_len < 64:
		ret_val = '0' + ret_val

	return '04' + ret_val


class DiffHell:
	def __init__(self):
		# of type EllipticCurvePrivateKey
		self.priv_key = ec.generate_private_key(ec.SECP256K1())
		self.publ_key = self.priv_key.public_key()
		self.cipher = None
		self.secret_key = None
		self.iv = 0

	def gen_shared(self, public_key):
		shared_key = self.priv_key.exchange(ec.ECDH(), public_key)
		return shared_key
	
	def init_cipher(self, sk):
		self.secret_key = sk
		self.cipher = Cipher(algorithms.AES(sk), modes.CBC(self.iv))
	
	def encrypt_msg(self, plain_bytes):
		encryptor = self.cipher.encryptor()
		cipher_text = encryptor.update(plain_bytes) + encryptor.finalize()
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
	response = trn(pcsc.asciiToHex('00220000') + ln(uncompress(dh.publ_key)), expsw = 0x9000, descr = 'Generate shared secret')

	card_pubk_x = int.from_bytes(response[1:33], 'big')
	card_pubk_y = int.from_bytes(response[33:65], 'big')
	
	card_publ_key = ec.EllipticCurvePublicNumbers(card_pubk_x, card_pubk_y, ec.SECP256K1())
	host_shared = dh.gen_shared(card_publ_key.public_key())

	print("\nHost public key : ", uncompress(dh.publ_key))
	print("Card  public key: ", hexToAscii(response[0:65]))
	print("Host  shared key: ", hexToAscii(host_shared))
	print("Card  shared key: ", hexToAscii(response[65:-2]))

	print("Are values equal? ", hexToAscii(host_shared) == hexToAscii(response[65:-2]))
	pcsc.disconnect(card)

main_func()