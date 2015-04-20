import cv2
import hashlib
import math
import numpy as np
import os
import re

""" Load if exists """
try:
    from cryptography.fernet import Fernet
except Exception:
    pass

class StegaBits:

    def __init__(self, path, secret_key=None, seed=None):
        """ Class constructor
        path:       Path to visible image
        secret_key: Shared secret key using cryptography.fernet. Leave None to not use
        seed:       Not implemented yet but will be used to set random seed for lsb bit distribution
        """
        self.path = path
        self.__secret_key = secret_key
        self.__seed = seed
        self.__checksum_bit_cnt = len(hashlib.sha256('test').hexdigest()) * 8
        self.__image_header_bit_cnt = self.__checksum_bit_cnt
        self.__null = '000011010000110100001101'
        self.__reserved_bits = (self.__checksum_bit_cnt * 2) + (self.__image_header_bit_cnt)
        if self.__secret_key != None:
            self.__check_cryptography()
            self.__cipher = Fernet(self.__secret_key)
        self.__open()

    def __bit_str_to_str(self, bit_str):
        """ Converts a binary bit string of 0s and 1s, e.g.,(01001011) into its ASCII string representation
        bit_str: The binary bit string,'0101010' to convert
        return:  The ASCII string representation
        """
        pos = 0
        text = []
        while(pos < len(bit_str)):
            text.append(chr(int(bit_str[pos:pos+8],2)))
            pos += 8
        return ''.join(text)

    def __byte_to_bit_str(self, byte):
        """ Converts a byte into into its binary string representation
        byte:   A byte
        return: The binary bit string representation
        """
        return bin(byte)[2:].zfill(8)

    def __check_cryptography(self):
        """ Checks if cryptography is installed
        return: Throws exception if package is not found
        """
        try:
            from cryptography.fernet import Fernet
        except Exception:
            raise Exception("You must install the cryptography package for d/encryption to work")

    def __decrypt(self, text):
        """ Decrypts the given ciphertext using the shared key. Note this will blow up if text is not encrypted
        text:   The ciphertext
        return: The decrypted plaintext
        """
        if self.__secret_key != None:
            return self.__cipher.decrypt(text)
        else:
            return text

    def __encrypt(self, text):
        """ Encrypts the given plaintext using the shared key
        text:   The plaintext
        return: The encrypted ciphertext
        """
        if self.__secret_key != None:
            return self.__cipher.encrypt(text)
        else:
            return text

    def __get_bits_by_cnt(self, bit_cnt, offset):
        """ Returns LSBs from given offset to count
        bit_cnt: The number of LSB bits to return
        offset:  Offset from starting LSB in visible image
        return:  Binary bit string representation of the LSB or None if something goes wrong
        """
        bits = []
        image = self.image.flatten()
        max_bit = self.height * self.width * 8
        if bit_cnt > (max_bit - offset):
            raise Exception("Exceeded image dimensions for getting bits")
        for i in range(0, bit_cnt):
            bits.append(image[offset] & 1) #lsb
            offset += 1
        if len(bits) < 1:
            return None
        return ''.join(map(str,bits))

    def __get_bits_by_null(self, offset):
        """ Returns LSBs from given offset until bit pattern '000011010000110100001101' (aka NULL)
        offset: Offset from starting LSB in visible image
        return: Binary bit string representation of the LSB or None if something goes wrong
        """
        null = re.compile(self.__null)
        found_flag = False
        text = ''
        byte = ''
        image = self.image.flatten()[offset:]
        for i in range(0, len(image)):
            byte = "%s%s" %(byte, str((image[i] & 1))) #lsb
            if len(byte) == 8:
                text = "%s%s" %(text, byte)
                if not null.search(text):
                    byte = ''
                else:
                    found_flag = True
                    break
        if found_flag == False:
            return None
        return text[0:-len(self.__null)]

    def __get_checksum_offsets(self):
        """ Returns the offset values for the text and image checksums
        return: Hidden text and image offset values stored in visible image
        """
        text_offset = 0
        image_offset = self.__checksum_bit_cnt
        return [text_offset, image_offset]

    def get_image(self):
        """ Extracts and returns the hidden image from the visible image
        return: The hidden image or None if not found
        """
        image_info = self.get_image_info()
        if image_info == None:
            return None
        dimensions = image_info['height'] * image_info['width']
        bit_cnt = dimensions * 8
        bits = self.__get_bits_by_cnt(bit_cnt, image_info['offset'])
        if bits == None:
            return None
        offset = 0
        image = np.zeros(dimensions, dtype=np.uint8)
        for i in range(0, dimensions):
            image[i] = int(bits[offset:offset+8], 2)
            offset += 8
        image = np.reshape(image, (image_info['height'], image_info['width']))
        return image

    def get_image_checksum(self):
        """ Extracts from the visible image the hidden image's checksum value
        return: The hex representation of the checksum value, but as a string or None if not found
        """
        if not self.has_image():
            return None
        bits = self.__get_bits_by_cnt(self.__checksum_bit_cnt, self.__get_checksum_offsets()[1])
        return self.__bit_str_to_str(self.__get_bits_by_cnt(self.__checksum_bit_cnt, self.__checksum_bit_cnt))

    def __get_image_header_offset(self):
        """ Returns the fixed image header LSB offset from within the visible image
        return: The offset
        """
        return (self.__checksum_bit_cnt * 2)

    def get_image_info(self):
        """ Extracts from the visible image details about the hidden image
        return: The hidden image information or None if not found
        """
        if not self.has_image():
               return None
        image_info = {}
        header_bits = self.__get_bits_by_cnt(self.__image_header_bit_cnt, self.__get_image_header_offset())
        results = header_bits.split(self.__null)
        if len(results) < 4:
            return None
        image_info['height'] = int(self.__bit_str_to_str(results[0]))
        image_info['width'] = int(self.__bit_str_to_str(results[1]))
        image_info['offset'] = int(self.__bit_str_to_str(results[2]))
        image_info['seed'] = int(self.__bit_str_to_str(results[3]))
        image_info['checksum'] = self.get_image_checksum()
        return image_info

    def __get_image_offset(self):
        """ Extracts from the visible the hidden image's offset location
        return: The hidden image's offset or None if not found
        """
        offset = (self.__checksum_bit_cnt * 2) + self.__image_header_bit_cnt
        if self.has_text():
            text = self.__get_text()
            if text != None:
                offset += (len(text) * 8) + len(self.__null)
        return offset

    def __get_text(self):
        """ Retrieves hidden text from visible image without encryption. This is
            a hack for now since there are times we don't want to decrypt even though
            encryption is enabled
        return: The hidden text or None if not found
        """
        text = self.__get_bits_by_null(self.__get_text_offset())
        if text == None:
            return None
        return self.__bit_str_to_str(text)

    def get_text(self):
        """ Retrieves hidden text from visible image with or without encryption enabled
        return: The hidden text or None if not found
        """
        text = self.__get_bits_by_null(self.__get_text_offset())
        if text == None:
            return None
        return self.__decrypt(self.__bit_str_to_str(text))

    def get_text_checksum(self):
        """ Extracts from the visible image the hidden text's checksum value
        return: The hex representation of the checksum value, but as a string or None if not found
        """
        if not self.has_text():
            return None
        return self.__bit_str_to_str(self.__get_bits_by_cnt(self.__checksum_bit_cnt, 0))

    def get_text_info(self):
        """ Extracts from the visible image details about the hidden text
        return: The hidden text information or None if not found
        """
        if not self.has_text():
               return None
        text_info = {}
        text_info['checksum'] = self.get_text_checksum()
        text_info['offset'] = self.__get_text_offset()
        text_info['length'] = len(self.__get_text())
        return text_info

    def __get_text_offset(self):
        """ Returns the fixed offset for the hidden text
        return: The hidden text offset
        """
        return ((self.__checksum_bit_cnt * 2) + self.__image_header_bit_cnt)

    def has_image(self):
        """ Returns true if hidden image exists otherwise false
        return: True or False
        """
        bits = self.__get_bits_by_cnt(self.__checksum_bit_cnt, self.__get_checksum_offsets()[1])
        if bits == None:
            return False
        return (bits[0:len(self.__null)] != self.__null)

    def has_text(self):
        """ Returns true if hidden text exists otherwise false
        return: True or False
        """
        bits = self.__get_bits_by_cnt(self.__checksum_bit_cnt, self.__get_checksum_offsets()[0])
        if bits == None:
            return False
        return (bits[0:len(self.__null)] != self.__null)

    def hide(self, text, image_path, resize=False):
        """ Hides the given text and/or image
        text:       The text to hide or None
        image_path: The path to the image to hide
        resize:     Optional flag to resize the hidden image prior to hiding -- doesn't work well
        """
        if text == None and image_path == None:
            raise Exception("You must specify at least some text and/or an image")
        self.__hide_text(text)
        self.__hide_image(image_path, resize)

    def __hide_image(self, path, resize=False):
        """ Hides the given image. If path is empty or set to None then bits will be set to indicate
            no hidden image in the visible image. The has_image() function uses this bit to check
        image_path: The path to the image to hide
        resize:     Optional flag to resize the hidden image prior to hiding -- doesn't work well
        """
        checksum = self.__null
        if path != None:
            path = path.strip()
            if path == "":
                path = None
        checksum_offset = self.__get_checksum_offsets()[1]
        if path == None:
            self.__set_bits(self.__null, checksum_offset)
            return
        else:
            self.__open_hidden(path, resize)
            self.__set_bits(self.str_to_bit_str(self.hidden_image['checksum']), checksum_offset)
        seed = self.__seed
        if seed == None:
            seed = 0

        # Embed the image information first
        height_bits = "%s%s" %(self.str_to_bit_str(str(self.hidden_image['height'])), self.__null)
        width_bits = "%s%s" %(self.str_to_bit_str(str(self.hidden_image['width'])), self.__null)
        offset_bits = "%s%s" %(self.str_to_bit_str(str(self.__get_image_offset())), self.__null)
        seed_bits = "%s%s" %(self.str_to_bit_str(str(seed)), self.__null)
        image_header_bits = "%s%s%s%s" %(height_bits, width_bits, offset_bits, seed_bits)
        self.__set_bits(image_header_bits, self.__get_image_header_offset())

        # Spread out the hidden image's bits to the least significant bits of the visible image
        # TODO: Maybe we can do this pseudo-randomly distribute the bits.  Bob can reconstruct using same seed.
        offset = self.__get_image_offset()
        shape = self.hidden_image['image'].shape
        hidden_image = self.hidden_image['image']
        hidden_image = self.hidden_image['image'].flatten()
        bits = ''
        for pixel in hidden_image:
            bits += self.__byte_to_bit_str(pixel)
        self.__set_bits(bits, offset)
        return

    def __hide_text(self, text):
        """ Hides the given text. If path is empty or set to None then bits will be set to indicate
            no text in the visible image. The has_text() function uses this bit to check
        text: The text to hide
        """
        checksum_offset = self.__get_checksum_offsets()[0]
        if text == None:
            self.__set_bits(self.__null, checksum_offset)
        else:
            self.__set_bits(self.str_to_bit_str(hashlib.sha256(text).hexdigest()), checksum_offset)
            self.__set_bits("%s%s" %(self.str_to_bit_str(self.__encrypt(text)), self.__null), self.__get_text_offset())

    def __open(self):
        """ Opens the visible image. Depending on the context the image may be pristine or already
            contain the Steganography data
        """
        self.__reset()
        if not os.path.isfile(self.path):
            raise Exception("Visible image file doesn't exist: %s" %(self.path))
        self.image = cv2.imread(self.path)
        self.height = self.image.shape[0]
        self.width = self.image.shape[1]
        self.channels = self.image.shape[2]
        if (self.height * self.width * self.channels) < self.__reserved_bits:
            raise Exception("Sorry image dimensions are too small to use for this application")


    def __open_hidden(self, path, resize=False):
        """ Opens the hidden image.
        path:   Path to the hidden image
        resize: Option to resize the image prior to embedding
        """
        if not os.path.isfile(path):
            raise Exception("Hidden image file doesn't exist: %s" %(self.path))
        if (resize == False):
            self.hidden_image['image'] = cv2.cvtColor(cv2.imread(path), cv2.COLOR_BGR2GRAY)
            self.hidden_image['checksum'] = hashlib.sha256(self.hidden_image['image']).hexdigest()
            self.hidden_image['height'] = self.hidden_image['image'].shape[0]
            self.hidden_image['width'] = self.hidden_image['image'].shape[1]
            return
        self.hidden_image['image'] = cv2.cvtColor(cv2.imread(path), cv2.COLOR_BGR2GRAY)
        width = int(math.floor(self.width * .5))
        height = int(math.floor(self.height * .5))
        adjusted_width = self.hidden_image['image'].shape[0]
        adjusted_height = self.hidden_image['image'].shape[1]
        while True:
            if adjusted_width <=  width and adjusted_height <= height:
                break;
            adjusted_width = int(math.floor(adjusted_width * .99))
            adjusted_height = int(math.floor(adjusted_height * .99))
        self.hidden_image['image'] = cv2.resize(self.hidden_image['image'],(adjusted_width, adjusted_height))
        self.hidden_image['checksum'] = hashlib.sha256(self.hidden_image['image']).hexdigest()
        self.hidden_image['height'] = self.hidden_image['image'].shape[0]
        self.hidden_image['width'] = self.hidden_image['image'].shape[1]

    def __reset(self):
        """ Resets internal variables to an uninitialized state
        """
        self.image = None
        self.width = None
        self.height = None
        self.channels = None
        self.hidden_image = {}

    def save(self, path):
        """ Saves the  visible image to file. The state of the image depends on if
        already modified or loaded as a modified image or still pristine
        path: Path to save file
        """
        cv2.imwrite(path, self.image)

    def __set_bits(self, bit_str, offset):
        """ Sets the LSBs in the visible image
            bit_str: Binary bit string representation of the LSBs
            offset: The bit offset in visible image
        """
        shape = self.image.shape
        self.image = self.image.flatten()
        bit_cnt = len(bit_str)
        max_bit = self.height * self.width * 8
        if bit_cnt > (max_bit - offset):
            raise Exception("Exceeded image dimensions for setting bits")
        for i in range(0, bit_cnt):
            self.image[offset] = self.__set_lsb(self.image[offset], bit_str[i])
            offset += 1
        self.image = np.reshape(self.image, shape)

    def __set_lsb(self, byte, bit):
        """ Performs bitwise operations for given byte and bit. 
        byte: Byte from the visible image
        bit:  Bit from the a hidden component that will be used to set the bit
              byte from the visible image
        """
        if bit == '1':
            return byte | 1
        else:
            return byte & ~1

    def show(self, title=''):
        """ Displays the visible image in its current state
        title: Optional title shown in window
        """
        cv2.imshow(title, self.image)
        cv2.waitKey(0)

    def show_image(self, title=''):
        """ Extracts and displays the hidden image
        title: Optional title shown in window
        """
        cv2.imshow(title, self.get_image())
        cv2.waitKey(0)

    def show_images(self, title=''):
        """ Extracts and displays the visible, hidden image and text
        title: Optional title shown in window
        """
        image = self.get_image()
        image = np.reshape(image, image.shape + (1,))
        image_info = self.get_image_info()
        text_info = self.get_text_info()
        x0 = (int(math.floor(self.width / 2)) - int(math.floor(image_info['width'] / 2)))
        x1 = x0 + image_info['width']
        y0 = (int(math.floor(self.height / 2)) - int(math.floor(image_info['height'] / 2)))
        y1 = y0 + image_info['height']
        merged_image = self.image
        merged_image[y0:y1,x0:x1] = image
        cv2.putText(merged_image,self.get_text(),(40,y1 + 20),cv2.FONT_HERSHEY_DUPLEX,.7,(102,255,255),thickness=2)
        cv2.imshow(title, self.image)
        cv2.waitKey(0)

    def str_to_bit_str(self, s):
        """ Converts a string into its binary bit string representation
        s:       The string to convert
        returns: The binary bit string representation
        """
        bit_str = ""
        i = 0
        for c in s:
            bit_str = "%s%s" %(bit_str, bin(ord(c))[2:].zfill(8))
            i += 1
        return bit_str
