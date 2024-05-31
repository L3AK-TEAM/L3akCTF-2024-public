#!/usr/bin/python3

from common import symbol_width, symbol_height, get_symbol_images, base64_png_to_cv2_image, num_captchas
from server import load_patterns, generate_random_captcha, request_sample_data
from solver import split_image, find_all_matching_image_labels, find_matching_captcha_label

symbols = get_symbol_images()
patterns = load_patterns()

def test_single_image_detection_by_label(expected_label):
	'''
	Tests the detection of a single symbol paired with each pattern using the provided solver.
	'''
	# For easier testing, set this to 1.
	num_symbols_per_captcha = 1
	print(f'Testing label {expected_label}.')
	for pattern_index in range(len(patterns)):
		pattern = patterns[pattern_index]
		created_label, captcha = generate_random_captcha({ expected_label : symbols[expected_label] }, [pattern], num_symbols_per_captcha)
		assert(expected_label == created_label)
		# Convert base64 string to cv2 image.
		img = base64_png_to_cv2_image(captcha)
		sliced_image = split_image(img, num_symbols_per_captcha)
		assert(len(sliced_image) == 1)
		assert(sliced_image[0].shape == img.shape)
		assert(sliced_image[0].shape[0] == symbol_height)
		assert(sliced_image[0].shape[1] == symbol_width)
		matching_labels = find_all_matching_image_labels(sliced_image[0])
		if len(matching_labels) != 1:
			print(expected_label, len(matching_labels), matching_labels, pattern_index)
			print(captcha)
		assert(len(matching_labels) == 1)
		assert(matching_labels[0] == expected_label)

def test_single_image_detection():
	'''
	Tests the detection of each individual image paired with each pattern using the provided solver (using test_single_image_detection_by_label).
	'''
	# Test each symbol
	for expected_label in symbols:
		test_single_image_detection_by_label(expected_label)

def test_random_captcha_detection(num_tests):
	'''
	Tests the detection of each individual image using the provided solver.
	'''
	# Test multiple times:
	for idx in range(num_tests):
		print(f'Testing random captcha {idx + 1} / {num_tests}.')
		expected_label, captcha = generate_random_captcha(symbols, patterns)
		# Convert base64 string to cv2 image.
		captcha_image = base64_png_to_cv2_image(captcha)
		restored_label = find_matching_captcha_label(captcha_image)
		assert(restored_label == expected_label)

def run_all_tests():
	'''
	Run all the specified tests to check if everything is working as expected.
	'''
	# Testing the detection of all combinations of symbols and patterns:
	print('Testing single symbol detection for all combinations of symbols and patterns:')
	test_single_image_detection()
	# Testing the challenge a couple of times over whilst timing the solver.
	print('Testing the challenge 10 times, verifying that the detection, using the sample-solver, works.')
	times = []
	amount = 1
	for _ in range(amount):
		import time
		start_time = time.time()
		test_random_captcha_detection(num_captchas)
		end_time = time.time()
		times += [end_time - start_time]
	print(f'Elapsed times for {amount} sets of {num_captchas} captchas: {times}. This averages {sum(times) / amount} seconds per set.')
	# Testing the output of the sample data.
	request_sample_data()
	# All tests completed successfully:
	print('All tests completed successfully!')

if __name__ == '__main__':
	run_all_tests()
