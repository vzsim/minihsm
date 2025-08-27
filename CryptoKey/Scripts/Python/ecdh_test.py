from tinyec import registry
from tinyec import ec

import secrets
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


def compress(public_key):
	return hex(public_key.x)[2:] + hex(public_key.y % 2)[2:]

def uncompress(public_key):
	ret_val = hex(public_key.x)[2:] + hex(public_key.y)[2:]
	ret_val_len = ln(ret_val)[0]
	
	# padd the leading zero for the MSB (if required)
	if ret_val_len < 64:
		ret_val = '0' + ret_val

	return '04' + ret_val

def process():
	global context
	global card
	global protocol
	response = 0

	curve = registry.get_curve('secp256r1')
	# alice_priv_key = 3
	alice_priv_key = secrets.randbelow(curve.field.n)
	alice_publ_key = alice_priv_key * curve.g

	context, card, protocol = pcsc.openCardAnyReader(readers_list)
	trn(pcsc.asciiToHex('00A40400') + ln('A00000000101'), expsw = 0x9000, descr = 'Select CryptoKey')
	response = trn(pcsc.asciiToHex('00220000') + ln(uncompress(alice_publ_key)), expsw = 0x9000, descr = 'Generate shared secret')

	card_publ_raw = response[0:65]
	card_shared_raw = response[65:-2]

	# card_shared_packed = ec.Point(curve, card_shared_raw[1:32], card_shared_raw[32:])
	card_publ_int = int("".join(map(str, card_publ_raw)))
	alice_shared_key = alice_priv_key * curve.g * card_publ_int
	

	print("\nAlice public key (uncompressed): ", uncompress(alice_publ_key))
	print("\nAlice shared key               : ", uncompress(alice_shared_key)[2:])

	print("\nCard public key (uncompressed) : ", hexToAscii(card_publ_raw))
	print("\nCard shared key (as int)       : ", hexToAscii(card_shared_raw)[2:])

	pcsc.disconnect(card)

process()