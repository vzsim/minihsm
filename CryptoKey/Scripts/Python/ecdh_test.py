from tinyec import registry
import secrets
import pythonSC as pcsc

readers_list = ['']

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


def compress(public_key):
	return hex(public_key.x)[2:] + hex(public_key.y % 2)[2:]

def uncompressed(public_key):
	return hex(public_key.x)[2:] + hex(public_key.y)[2:]

def process():
	global context
	global card
	global protocol

	
	curve = registry.get_curve('brainpoolP256r1')
	response = 1
	alice_priv_key = response
	# alice_priv_key = secrets.randbelow(curve.field.n)
	alice_publ_key = alice_priv_key * curve.g


	
	print("Alice private key y            : ", hex(alice_priv_key)[2:])
	print("Alice public key (uncompressed): ", uncompressed(alice_publ_key))
	print("Alice public key (compressed)  : ", compress(alice_publ_key))

	context, card, protocol = pcsc.openCardAnyReader(readers_list)
	trn(pcsc.asciiToHex('00A40400') + ln('A00000000101'), expsw = 0x9000, descr = 'Select CryptoKey')
	trn(pcsc.asciiToHex('00220000') + ln(uncompressed(alice_publ_key)), expsw = 0x9000, descr = 'Generate shared secret')
	# response = trn(pcsc.asciiToHex('00220200'), expsw = 0x9000, descr = 'Get card\'s private key')[:-2]

	pcsc.disconnect(card)

process()