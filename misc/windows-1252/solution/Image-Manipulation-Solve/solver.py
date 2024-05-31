#!/usr/bin/python3

import time # for the timing of the clients responses
from pwn import * # to connect with the server
from common import symbol_width, symbol_height, get_symbol_images, num_symbols_per_captcha, base64_png_to_cv2_image, is_white, color_blue, num_captchas


# Connection details:
server = '127.0.0.1'
port = 8448


symbols = get_symbol_images()

def pixels_equal(pixel1, pixel2):
	'''
	Returns True, if the pixels have the same color.
	'''
	return pixel1[0] == pixel2[0] and pixel1[1] == pixel2[1] and pixel1[2] == pixel2[2]

def split_image(image, num_symbols_per_captcha = num_symbols_per_captcha):
	'''
	Splits a single image into multiple smaller images.
	'''
	images = []
	for idx in range(0, image.shape[1], symbol_width):
		images += [image[:, idx:idx + symbol_width]]
	return images

def find_all_matching_image_labels(image):
	'''
	The solver:
	Detect any matching image for the provided image and return all corresponding labels.
	'''
	#print(image)
	matching_labels = []
	for label, symbol in symbols.items():
		symbol_matches = True
		# Check if any pixel violates the color constraints:
		for y in range(symbol_height):
			for x in range(symbol_width):
				if pixels_equal(image[y, x], color_blue):
					# If the image has an overlay at this pixel, do not check the other constraints; just check if the symbol is white:
					if not is_white(symbol[y, x]):
						# if the image-pixel is blue from the overlay, then the symbol should be white.
						symbol_matches = False
						break
				elif not pixels_equal(symbol[y, x], image[y, x]):
					# if the image does not have an overlay at this pixel, the colors should be identical to the symbol!
					symbol_matches = False
					break
			if not symbol_matches:
				break
		# If no pixel violates the color constraints, this symbol is a match:
		if symbol_matches:
			matching_labels += [label]
	return matching_labels

def find_matching_label_for_character_image(character_image):
	'''
	The solver:
	Returns the matching label for the provided image representing one character, assuming there is only one match.
	'''
	return find_all_matching_image_labels(character_image)[0]

def find_matching_captcha_label(captcha_image):
	'''
	The solver:
	Returns the matching label for the provided image, assuming there is only one match.
	'''
	images = split_image(captcha_image)
	labels = [find_matching_label_for_character_image(img) for img in images]
	return ''.join(labels)

def main():
	conn = remote(server, port)
	# Read intro and send '1' to start the challenge:
	conn.sendlineafter(b'> ', b'1')
	# Process the captchas:
	start_time = time.time()
	for idx in range(num_captchas):
		print('Solving captcha no.', idx)
		# Read the challenge:
		response = conn.recvline().decode().strip()
		# Parse response:
		if response[0] != 'C':
			# No new captcha
			print(idx, response)
			break
		# Discard the following input prompt:
		conn.recvuntil(b'> ')
		# Discard the 'Captcha #idx: ' bit of the response and get the base64 encoded image data:
		base64_captcha_imgage = response[response.index(': ') + 2:]
		# Convert the base64 encoded image into a cv2 image:
		captcha_image = base64_png_to_cv2_image(base64_captcha_imgage)
		# Compute the label for the captcha:
		label = find_matching_captcha_label(captcha_image)
		# Write the response:
		conn.sendline(label.encode())
	print(f'Total time to solve the challenge: {time.time() - start_time} seconds.')
	# Read the flag:
	print(conn.recvuntil(b'Bye, bye.').decode())
	conn.close()

if __name__ == '__main__':
	main()
