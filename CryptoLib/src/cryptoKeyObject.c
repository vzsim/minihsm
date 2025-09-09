#include "pkcs11-cryptolib.h"
#include <stdlib.h>

/*
	the list of currently supported attributes:
	CKA_KEY_TYPE
	CKA_ID
	CKA_LABEL
*/

static void
put_short(uint8_t* array, CK_ULONG value)
{
	array[0] = ( value       & 0xFF);
	array[1] = ((value >> 8) & 0xFF);
}

static void
serialize(CK_ATTRIBUTE_PTR attributes, CK_ULONG attrLen, uint8_t* array)
{
	for (CK_ULONG i = 0, offset = 0; i < attrLen; ++i) {
		put_short(array + offset, attributes[i].type);	// store Tag
		offset += 2;
		
		put_short(array + offset, attributes[i].ulValueLen); // store Length
		offset += 2;

		memcpy(array + offset, attributes[i].pValue, attributes[i].ulValueLen); // store Value
		offset += attributes[i].ulValueLen;
	}
}

/**
 * @brief Serializes a private key.
 * 
 * This function stores the list of attributes as the sequence of TLV structtures,
 * where the Tag and Length fields are composed of 2 bytes, and the Value field has
 * variable length.
 * 
 * The Tag field stores the CK_ATTRIBUTE_TYPE value, but for the sake of saving memory
 * we use only the first two octets.
 * @param attributes.
 * @param atrLen the length of input array of CK_ATTRIBUTE structures.
 * @param arrayLen the lengh of output array
 */
uint8_t*
serialize_private_key(CK_ATTRIBUTE_PTR attributes, CK_ULONG attrLen, CK_ULONG_PTR arrayLen)
{
	arrayLen = 0;
	uint8_t* array = NULL;

	// Count the total number of bytes.
	for (CK_ULONG i = 0; i < attrLen; ++i) {
		*arrayLen += attributes[i].ulValueLen;
	}

	// the attributes[i].ulValueLen takes into account only the length of
	// attributes[i].pValue field.
	// We need to add another four bytes for each 'Tag' and 'Length' fields too.
	*arrayLen += attrLen * 4;

	array = malloc(*arrayLen);
	if (array == NULL) {
		return array;
	}

	serialize(attributes, attrLen, array);

	return array;
}