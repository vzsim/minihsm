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


class AESClass:
	def __init__(self):
		self.cipher = None
		self.iv = bytearray(16)

	def init_cipher(self, sk):
		self.cipher = Cipher(algorithms.AES(sk), modes.CBC(bytearray(16)))
	
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
	dh = AESClass()

	context, card, protocol = pcsc.openCardAnyReader(readers_list)

	trn(pcsc.asciiToHex('00A40400') + ln('A00000000101'), expsw = 0x9000, descr = 'Select CryptoKey')
	trn(pcsc.asciiToHex('00200000') + ln('3131313131'),   expsw = 0x9000, descr = 'Verify PIN')
	
	dh.init_cipher(dh.iv)
	host_cipher = dh.encrypt_msg(bytearray(32))

	for i in range(1):
		print("\t\t*** INTER No", i + 1)
		card_cipher = trn(pcsc.asciiToHex('002A8480') + ln(hexToAscii(bytearray(32))), expsw = 0x9000, descr = 'PSO: AES encrypt')
		card_plain = trn(pcsc.asciiToHex('002A8084') + ln(hexToAscii(host_cipher)), expsw = 0x9000, descr = 'PSO: AES decrypt')

		print("host's cipher: ", hexToAscii(host_cipher))
		print("card's cipher: ", hexToAscii(card_cipher[:-2]))
		print("card's plain : ", hexToAscii(card_plain[:-2]))

	pcsc.disconnect(card)

main_func()