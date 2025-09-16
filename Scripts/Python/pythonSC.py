# functions:
# openCardConnection(readerName) : card, protocol - to open card reader
# transmit(card, protocol, request, descr=None) : response - exchange APDU
# options:
# connect(context, reader): context, card, dwActiveProtocol - power on
# disconnect(card): - power off

import time
from smartcard.scard import SCARD_SCOPE_USER, SCARD_S_SUCCESS, \
    SCARD_SHARE_SHARED, SCARD_UNPOWER_CARD, SCARD_PROTOCOL_T0, \
    SCARD_PROTOCOL_T1
from smartcard.scard import error, SCardEstablishContext, \
    SCardGetErrorMessage, SCardReleaseContext, SCardListReaders, SCardConnect,\
    SCardDisconnect, SCardStatus, SCardTransmit
from smartcard.util import toHexString
import collections.abc

ISO7816_INS = [
    (0x04, 'deactivate_file'),                 (0x0c, 'erase_record'),                 (0x0e, 'erase_binary'),
    (0x0f, 'erase_binary1'),                   (0x10, 'perform_scql_operation'),       (0x12, 'perform_transaction_operation'),
    (0x14, 'perform_user_operation'),          (0x20, 'verify'),                       (0x21, 'verify1'),
    (0x22, 'manage_security_environment'),     (0x24, 'change_reference_data'),        (0x26, 'disable_verification_requirement'),
    (0x28, 'enable_verification_requirement'), (0x2c, 'reset_retry_counter'),          (0x2a, 'perform_security_operation'),
    (0x44, 'activate_file'),                   (0x46, 'generate_asymmetric_key_pair'), (0x70, 'manage_channel'),
    (0x82, 'external_mutual_authenticate'),    (0x84, 'get_challenge'),                (0x86, 'general_authenticate'),
    (0x87, 'general_authenticate1'),           (0x88, 'internal_authenticate'),        (0xa0, 'search_binary'),
    (0xa1, 'search_binary1'),                  (0xa2, 'search_record'),                (0xa4, 'select'),
    (0xb0, 'read_binary'),                     (0xb1, 'read_binary1'),                 (0xb2, 'read_record'),
    (0xb2, 'read_record1'),                    (0xc0, 'get_response'),                 (0xc2, 'envelope'),
    (0xc3, 'envelope1'),                       (0xca, 'get_data'),                     (0xcb, 'get_data1'),
    (0xd0, 'write_binary'),                    (0xd1, 'write_binary1'),                (0xd2, 'write_record'),
    (0xd6, 'update_binary'),                   (0xd7, 'update_binary1'),               (0xda, 'put_data'),
    (0xdb, 'put_data1'),                       (0xdc, 'update_record'),                (0xdd, 'update_record1'),
    (0xe0, 'create_file'),                     (0xe2, 'append_record'),                (0xe4, 'delete_file'),
    (0xe6, 'terminate_df'),                    (0xe8, 'terminate_ef'),                 (0xfe, 'terminate_card_usage'),
    # non-stadard but commonly used
    (0x50, 'initialize_update'), (0xd8, 'put_key'), (0xf0, 'set_status'), (0xf2, 'get_status') ]

ISO7816_SW = [
    (0x9000, 'no_error'),                      (0x6100, 'bytes_remaining'),
    # warnings, NVM state was not changed - 0x62
    (0x6200, 'warning_state_unchanged'),       (0x6281, 'returned_data_corrupted'),    (0x6282, 'eof_reached'),
    (0x6283, 'selected_file_not_valid'),       (0x6284, 'control_info_not_formatted'), (0x6285, 'selected_file_terminated'),
    (0x6286, 'no_sensors_input'),              (0x6287, 'record_deactivated'),
    # warnings, NVM state was changed - 0x63
    (0x6300, 'warning_state_changed'),         (0x6381, 'warning_file_full'),          (0x63C0, 'wrong_secret_code'),
    # exectuion errors, NVM state not changed - 0x64
    (0x6400, 'execution_error'),               (0x6401, 'direct_response'),
    # execution errors, NVM state changed - 0x65
    (0x6500, 'memory_error'),                  (0x6581, 'memory_failure'),
    # incorrect length - 0x67
    (0x6700, 'wrong_length'),
    # class errors - 0x68 
    (0x6881, 'logical_channel_not_supported'), (0x6882, 'secure_messaging_not_supported'), (0x6883, 'last_command_expected'),
    (0x6884, 'command_chaining_not_supported'),
    # command not allowed
    (0x6982, 'security_status_not_satisfied'), (0x6983, 'file_invalid'),               (0x6984, 'data_invalid'),
    (0x6985, 'conditions_not_satisfied'),      (0x6986, 'command_not_allowed'),        (0x6999, 'applet_select_failed'),
    # incorrect parameters - 0x6A
    (0x6A80, 'wrong_data'),                    (0x6a81, 'func_not_supported'),         (0x6a82, 'file_not_found'),
    (0x6a83, 'record_not_found'),              (0x6a84, 'file_full'),                  (0x6a86, 'incorrect_p1p2'),
    # incorrect parameters (general) - 0x6B
    (0x6b00, 'wrong_p1p2'),
    # incorrect length, correct valud in second byte - 0x6C
    (0x6c00, 'correct_length'),
    (0x6d00, 'instruction_not_supported'),
    (0x6e00, 'class_not_supported'),
    (0x6f00, 'unknown') ]


def openCardAnyReader(reqReaders):
    context = openContext()
    readers = getReaders(context)  # get readers list and print their names
    if len(readers) < 1:
        closeContext(context)
        quit()
    card = 0
    for readerName in reqReaders:
        print('try to open reader: ' + readerName)
        for reader in readers:
            if (reader == readerName):
                card, protocol = connect(context, reader)
                break
        if (card == 0):
            print("reader not found")
            continue
        break
    if (card == 0):
        closeContext(context)
        quit()
    return context, card, protocol

def openCardConnection(readerName):
    context = openContext()
    readers = getReaders(context)  # get readers list and print their names
    if len(readers) < 1:
        closeContext(context)
        quit()
    card = 0
    print('try to open reader: ' + readerName)
    for reader in readers:
        if (reader == readerName):
            card, protocol = connect(context, reader)
            break
    if (card == 0):
        print("reader not found")
        closeContext(context)
        quit()
    return context, card, protocol


def openContext():
    result, context = SCardEstablishContext(SCARD_SCOPE_USER)
    if result != SCARD_S_SUCCESS:
        print('Failed to establish context: ' + SCardGetErrorMessage(result))
    else:
        print('Context established!')
    return context


def closeContext(context):
    result = SCardReleaseContext(context)
    if result != SCARD_S_SUCCESS:
        raise error('Failed to release context: ' +
                    SCardGetErrorMessage(result))
    print('Released context.')


def getReaders(context, mask=''):
    result, readers = SCardListReaders(context, [])
    if result != SCARD_S_SUCCESS:
        print('Failed to list readers: ' + SCardGetErrorMessage(result))
    elif len(readers) < 1:
        print('No smart card readers')
    else:
        print('PCSC Readers:')
        for reader in readers:
            print('    ', reader)
    return readers


def connect(context, reader):
    result, card, dwActiveProtocol = \
        SCardConnect(context, reader, SCARD_SHARE_SHARED,
                     SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
    if result != SCARD_S_SUCCESS:
        print('Unable to connect: ' + SCardGetErrorMessage(result))
    else:
        getInfo(card, dwActiveProtocol)
    return card, dwActiveProtocol


def disconnect(card):
    result = SCardDisconnect(card, SCARD_UNPOWER_CARD)
    if result != SCARD_S_SUCCESS:
        print(' Failed to disconnect: ' + SCardGetErrorMessage(result))
    else:
        print()
        print('Disconnected')


def getInfo(card, dwActiveProtocol):
    result, reader, state, protocol, atr = SCardStatus(card)
    if result != SCARD_S_SUCCESS:
        print('Failed to get status: ' + SCardGetErrorMessage(result))
    else:
        print()
        print('\"' + reader + '\" (T=' + str(dwActiveProtocol) + ')' +
            ' state: ' + hex(state))
        print('ATR:', toHexString(atr, 1))


def formatCmd(request):
    s = toHexString(request[0:4], 1)
    s = s + ' ' + toHexString(request[4:5], 1)
    if (len(request) > 5):
        s = s + ' ' + toHexString(request[5:], 1)
    return s


def formatResp(response):
    s = ""
    if (len(response) > 2):
        s = toHexString(response[0:len(response) - 2], 1) + ' '
    sw = toHexString(response[len(response) - 2:], 1)
    swvalue = (response[len(response) - 2] << 8) + response[len(response) - 1]
    for i in range(0, len(ISO7816_SW)):
        if (swvalue == ISO7816_SW[i][0]):
            sw = sw + ' - sw_' + ISO7816_SW[i][1]
            break
    s = s + sw
    return s


# debug C-APDU interception mechanism
debugCmds = [ ] #('8050000008  8E9F848520ACDAD6', '00004E3500116746304EFF020019DFABEED157EA7CA87D402984015E 9000') ]


def transmit(card, protocol, cmd, descr=None, expsw=None):
    print()
    startTime = 0
    difTime = 0
    if (descr is not None):
        print(descr)
    print('>> ' + formatCmd(cmd))
    
    # debug commands interception
    for dbg in debugCmds:
        if (asciiToHex(dbg[0]) == cmd):
            print("command intercepted")
            result = SCARD_S_SUCCESS
            response = asciiToHex(dbg[1])
            break
    else:
        # send to card
        startTime = time.time()
        result, response = SCardTransmit(card, protocol, cmd)
        difTime = time.time() - startTime
    if result != SCARD_S_SUCCESS:
        print('Failed to transmit: ' + SCardGetErrorMessage(result))
    else:
        rsp = ""
        if len(response) == 2 and (response[0] == 0x61 or response[0] == 0x6C):
            #print("rsp: " + toHexString(response))
            rsp = toHexString(response, 1)
            origsw = response
            subreqlen = response[1]
            if response[0] == 0x61:
                reqMore = [0x00, 0xC0, 0x00, 0x00] + [subreqlen]
            else:
                reqMore = cmd[0:4] + [subreqlen]
            response = []
            rsp = rsp + ', ' + formatCmd(reqMore)
            #print("cmd: " + toHexString(reqMore))
            startTime = time.time()
            result, response = SCardTransmit(card, protocol, reqMore)
            difTime = time.time() - startTime
            if result != SCARD_S_SUCCESS:
                print('<< ' + toHexString(origsw))
                print('>> ' + formatCmd(reqMore))
                print('Failed to transmit: ' + SCardGetErrorMessage(result))
                exit(0)
            #print("response: " + toHexString(response))
            #input('stop')
        if (rsp != ""):
            rsp = '<< [' + rsp + '] '
        else:
            rsp = '<< '
        rsp = rsp + formatResp(response)
        print(rsp)
        
    if expsw != None:
        retsw = (response[-2] << 8) + response[-1]
        if (expsw != retsw):
            print('sw exp: ' + hex(expsw) + ' sw rcv: ' + hex(retsw))
        assert expsw == retsw

    difTime = time.time() - startTime
    print('Duration: ' + str(difTime))
    return response

def asciiToHex(asciistr):
    ar = []
    firstNibble = True
    bt = 0
    for i in range(0, len(asciistr)):
        ch = asciistr[i] 
        if (ch == '0'):                nibble = 0
        elif (ch == '1'):              nibble = 1
        elif (ch == '2'):              nibble = 2
        elif (ch == '3'):              nibble = 3
        elif (ch == '4'):              nibble = 4
        elif (ch == '5'):              nibble = 5
        elif (ch == '6'):              nibble = 6
        elif (ch == '7'):              nibble = 7
        elif (ch == '8'):              nibble = 8
        elif (ch == '9'):              nibble = 9
        elif (ch == 'A' or ch == 'a'): nibble = 10
        elif (ch == 'B' or ch == 'b'): nibble = 11
        elif (ch == 'C' or ch == 'c'): nibble = 12
        elif (ch == 'D' or ch == 'd'): nibble = 13
        elif (ch == 'E' or ch == 'e'): nibble = 14
        elif (ch == 'F' or ch == 'f'): nibble = 15
        else:                          continue
        if firstNibble:
            firstNibble = False
            bt = nibble << 4
        else:
            bt += nibble
            ar.append(bt)
            firstNibble = True
    return ar

# def hexToAscii(hexstr):
#     print(toHexString(hexstr, 1))
