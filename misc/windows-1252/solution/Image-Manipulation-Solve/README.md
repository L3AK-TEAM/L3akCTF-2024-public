# L3ak CTF 2024
Competition URL: https://ctf.l3ak.team/
## Overview

| Challenge       | Category | Points | Solves | Flag                                       |
| --------------- | -------- | ------ | ------ | ------------------------------------------ |
| Windows-1252    | misc     |  498   |    9   | L3AK{0pT!cal_chaR4Ct3R_R3cOgN!tIon_i5_fUN} |

## Challenge Author:
- [Matthias](https://github.com/0x-Matthias/)

## Writeup Author
- [Matthias](https://github.com/0x-Matthias/)

## Challenge: Windows-1252
How fast do you think you can solve captchas?

## Attachments
- [solver.py](./solver.py)
- [common.py](./common.py)

## Solution
In this challenge, you're required to solve 100 captchas, with 5 characters each, within 100 seconds to receive the flag. There are multiple ways to solve this challenge; this solution is based on pure image manipulation.

The solution to this challenge involves multiple steps:

### 1. Generate labeled reference images for each character
There's two possibilities to generate the labeled reference images:
1. The challenge did provide a base64 encoded string, which represented a png. In this image, all the required characters of the Windows-1252 charset were present, but shuffeled and not labeled. By cutting this image into 25x25 pixel images and manually labelling them, you could obtain your reference images.
2. The other option was to find and use the image on the `Windows-1252` Wikipedia page (c.f. [Resources](#resources) for the link to Wikipedia and the cropped image itself) and split that one to obtain the reference images. Please find the corresponding code in the `generate_symbols.py` linked in the [Resources](#files-used-to-generate-the-challenge) section and focus on this part:
   ```python
   def main():
   	[...]
       # Read the src-image for all the images.
   	img_all_symbols = cv2.imread(file_path_all_symbols)
   	# Determine the top left pixel for each symbol.
   	grid_points = find_grid_points(img_all_symbols)
   	# For each symbol extract the cropped image and save it to the output directory.
   	for idx in range(len(allowed_symbols)):
   		crop_and_save_symbol(img_all_symbols, grid_points, idx)
   	[...]
   ```

### 2. Detect a single noisy character
To make a detection using pure image manipulation feasable, we need a mechanism to distinguish between the actual character image and the noise overlayed on top. Luckily, the color scheme used in the character images does not use the RGB value of `(0, 0, 255)`, but the noise does only use this color. Based on this observation, we can write our script to detect a single character by ignoring the blue pixels and comparing all the other pixels. If none of the pixels deviate from the expected value, we can return the corresponding label.
```python
from common import symbol_width, symbol_height, get_symbol_images, color_blue, is_white

# Retrieve the dictionary of the labels and the symbol images
symbols = get_symbol_images()

def pixels_equal(pixel1, pixel2):
	'''
	Returns True, if the pixels have the same color.
	'''
	return pixel1[0] == pixel2[0] and pixel1[1] == pixel2[1] and pixel1[2] == pixel2[2]

def find_all_matching_image_labels(image):
	'''
	The solver:
	Detect any matching image for the provided image and return all corresponding labels.
	'''
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
```

Please refer to [common.py](#attachments) for the implementation of the functions
```python
def is_white(pixel)
```
which checks whether is pixel is white or not and
```python
def get_symbol_images()
```
which is basically just loading the character symbols generated in the [1. Generate labeled reference images for each character](#1-generate-labeled-reference-images-for-each-character) section.

### 3. Detecting an entire noisy captcha
To detect an entire captcha, you would basically need to detect 5 characters in sequence and then append their labels like so:
```python
from common import symbol_width, num_symbols_per_captcha

def split_image(image, num_symbols_per_captcha = num_symbols_per_captcha):
	'''
	Splits a single image into multiple smaller images.
	'''
	images = []
	for idx in range(0, image.shape[1], symbol_width):
		images += [image[:, idx:idx + symbol_width]]
	return images

def find_matching_captcha_label(captcha_image):
	'''
	The solver:
	Returns the matching label for the provided image, assuming there is only one match.
	'''
	images = split_image(captcha_image)
	labels = [find_matching_label_for_character_image(img) for img in images]
	return ''.join(labels)
```

### 4. Interacting with the challenge
Now, that we have the basic logic implemented, all we need to do is connect to the challenge server and implement the communication part:
```python
#!/usr/bin/python3

import time # for the timing of the clients responses
from pwn import * # to connect with the server
from common import base64_png_to_cv2_image, num_captchas

# Connection details:
server = '127.0.0.1'
port = 8448

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
```

### 5. Retrieve the flag
After setting the proper `connection details` in `solver.py`, you can retrieve the flag by running the `solver.py` script against the challenge server:
```L3AK{0pT!cal_chaR4Ct3R_R3cOgN!tIon_i5_fUN}```

## Resources
- [Wikipedia: Windows-1252 Codepage layout](https://en.wikipedia.org/wiki/Windows-1252#Codepage_layout)

### Files used to generate the challenge
- A cropped image, based on the Wikipedia: Windows-1252 Codepage layout: [all_symbols.png](../../build/all_symbols.png)
- Scripts to generate the character images from the code page image and to generate the noise patterns: [generate_symbols.py](../../build/generate_symbols.py)
- A test script to make sure, there's no noise pattern, that interferes with detection: [test.py](../../build/test.py)