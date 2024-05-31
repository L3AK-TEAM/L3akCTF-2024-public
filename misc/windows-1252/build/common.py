import os # for file system operations
import cv2 # "pip install opencv-python" for image processing
import numpy # for combining images
from base64 import b64decode # for base64 decoding

# Constants:
num_captchas = 100 # The number of captchas to solve successfully in one session.
num_symbols_per_captcha = 5 # Needs to be less or equal to the total number of symbols 'num_symbols'!
symbol_width = 25
symbol_height = 25
dir_symbols = os.path.abspath('./symbols/') # The directory containing the symbols.
file_path_sample_data = os.path.abspath('./sample_data.png')
dir_patterns = os.path.abspath('./patterns/') # The directory containing the patterns.
num_patterns = 32 # The number of different patterns to overlay over the symbols.
grid_color_grey = [176, 169, 162] # reversed RGB ordering, as used by cv2
color_blue = [0xff, 0x00, 0x00] # the color value for blue used in the symbols.
# Allowed symbols: (Almost) all prinable ascii/ansi according to "Windows codepage 1252"
allowed_symbols = [hex(x)[2:] for x in sorted(set(range(256)).difference(range(0x21), range(0x7F, 0xA1), [0xAD]))]

# Common functions:
def get_symbol_images():
	'''
	Returns the tagged images of all the symbols
	'''
	images = {}
	for idx in allowed_symbols:
		img = cv2.imread(os.path.join(dir_symbols, f'{idx}.png'))
		images[idx] = img
	return images

def concat_images(images):
	'''
	Concatenates all the images horizontally and returns the resulting image.
	'''
	return numpy.concatenate(images, axis=1) # axis=1 => horizontal concatenation

def base64_png_to_cv2_image(b64_string):
	'''
	Converts the b64_string into a cv2 image.
	'''
	return cv2.imdecode(numpy.asarray(bytearray(b64decode(b64_string.encode())), dtype="uint8"), cv2.IMREAD_COLOR)

def is_white(pixel):
	'''
	Returns True, if the pixel is considered to be white.
	'''
	return pixel[0] == 0xff and pixel[1] == 0xff and pixel[2] == 0xff
