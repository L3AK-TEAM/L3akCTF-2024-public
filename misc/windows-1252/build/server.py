#!/usr/bin/python3

import os # for file system operations
import random # for sampling the symbols to include in the captcha
import time # for the timing of the clients responses
import cv2 # for image processing
from base64 import b64encode # for transmission of the images
from common import num_captchas, num_symbols_per_captcha, num_patterns, dir_patterns, concat_images, is_white, color_blue, file_path_sample_data, get_symbol_images

# Constants:
time_limit_in_seconds = 0.2 * num_symbols_per_captcha * num_captchas # The time limit for the entire challenge

def request_sample_data():
	'''
	Returns all symbols in a pregenerated, random order as a single png.
	'''
	with open(file_path_sample_data, 'rb') as f:
		sample_data_bytes = f.read()
	print(f'Here is your sample data: {b64encode(sample_data_bytes).decode()}')

def load_patterns():
	'''
	Returns the patterns as a list.
	'''
	patterns = []
	for idx in range(num_patterns):
		with open(os.path.join(dir_patterns, str(idx) + '.pat'), 'r') as file_pattern:
			pattern_point_texts = [line.strip() for line in file_pattern if line.strip() != '']
		pattern = [(int(point[0]), int(point[1])) for point in [point_text.split('_') for point_text in pattern_point_texts]]
		patterns += [pattern]
	return patterns

def overlay_pattern(img, pattern):
	'''
	Overlays the specified pattern over the img and returns the result.
	'''
	resulting_image = img.copy()
	for point in pattern:
		if is_white(resulting_image[point[1], point[0]]):
			resulting_image[point[1], point[0]] = color_blue
	return resulting_image

def generate_random_captcha(images, patterns, num_symbols_per_captcha = num_symbols_per_captcha):
	'''
	Generates a random captcha and returns the label (as hex-string) and the png (as base64-string)
	'''
	random.seed() # To stop randcrack from working in any case, simply use a new seed every time.
	chosen_symbols = random.sample(sorted(images.keys()), num_symbols_per_captcha)
	label = ''.join([s for s in chosen_symbols])
	chosen_images = [overlay_pattern(images[symbol_name], random.choice(patterns)) for symbol_name in chosen_symbols]
	combined_image = concat_images(chosen_images)
	img = b64encode(cv2.imencode(".png", combined_image)[1].tobytes()).decode()
	return label, img

def start_challenge():
	'''
	Run the challenge.
	'''
	images = get_symbol_images()
	patterns = load_patterns()
	start_time = time.time()
	for count in range(num_captchas):
		label, img = generate_random_captcha(images, patterns)
		print(f'Captcha #{count + 1}: {img}')
		response = input('> ')
		# check time constraint
		end_time = time.time()
		duration_in_seconds = end_time - start_time
		if duration_in_seconds > time_limit_in_seconds:
			print('You have been too slow. Try again, once you have improved you skills.')
			return
		# check correctness of the captcha value
		if response.strip().lower() != label.lower():
			print('You failed to solve this captcha. Try again, once you have improved you skills.')
			return
	from secret import FLAG
	print(f'Congratulations, you\'ve done it. Here is your flag: {FLAG}')

def main():
	print(f'Can you solve {num_captchas} captchas in {time_limit_in_seconds} seconds? You\'ll receive base64 encoded images and you\'ll have to reply with the hex string of the symbols shown! E.g. if the image shows "L3AK", you\'ll need to respond with "4c33414b".')
	print('Options:')
	print('[0] Request sample data.')
	print('[1] Start the challenge.')
	print('[*] Enter anything else to exit immediately.')
	choice = input('> ')
	if choice == '0':
		request_sample_data()
	elif choice == '1':
		start_challenge()
	print("Bye, bye.")

if __name__ == '__main__':
	main()
