#!/usr/bin/python3

import os # for file system operations
import cv2 # "pip install opencv-python" for image processing
import random # for sampling
from common import symbol_width, symbol_height, dir_symbols, file_path_sample_data, allowed_symbols, get_symbol_images, concat_images, dir_patterns, num_patterns, grid_color_grey

# Constants:
file_path_all_symbols = os.path.abspath('./all_symbols.png')
symbol_x_offset = 8
symbol_y_offset = 5
min_points_per_pattern = 8
max_points_per_pattern = 24

def clear_output_directory():
	'''
	Remove all old symbol-data from "./symbols/" to be able to retry the symbol image creation.
	'''
	# Delete all the symbol images (if present):
	for f in os.listdir(dir_symbols):
		os.remove(os.path.join(dir_symbols, f))
	# Delete the sample data image:
	if os.path.exists(file_path_sample_data):
		os.remove(file_path_sample_data)
	# Clear the pattern directory:
	for f in os.listdir(dir_patterns):
		os.remove(os.path.join(dir_patterns, f))

def crop_and_save_symbol(original_image, grid_points, idx):
	'''
	Crops and saves the image for the symbol with ordinal value 'idx'.
	'''
	x_min = grid_points[int(allowed_symbols[idx], 16)][0] + symbol_x_offset
	y_min = grid_points[int(allowed_symbols[idx], 16)][1] + symbol_y_offset
	cropped_img = original_image[y_min:(y_min +  symbol_height), x_min:(x_min + symbol_width)]
	cv2.imwrite(os.path.join(dir_symbols, f'{allowed_symbols[idx]}.png'), cropped_img)

def find_grid_points(img):
	'''
	Returns the grid points, where the top left corner of each symbol is (ordered by their symbol index).
	'''
	img_width = img.shape[1]
	img_height = img.shape[0]
	idx = 0
	grid_points = []
	for y in range(img_height - 1):
		for x in range(img_width - 1):
			# A grid point (x,y) is given by having the color grid_color_grey, as well as the neighbouring pixels to the right (x+1,y)
			# and to the bottom (x,y+1) having the same color.
			if all(img[y, x] == grid_color_grey) and all(img[y + 1, x] == grid_color_grey) and all(img[y, x + 1] == grid_color_grey):
				grid_points += [(x, y)]
				idx += 1
	return grid_points

def generate_sample_data():
	'''
	Generates a random sample image of all the allowed symbols and saves it as file_path_sample_data.
	'''
	images = get_symbol_images()
	random_order = random.sample(allowed_symbols, len(allowed_symbols))
	sample_data = concat_images([images[idx] for idx in random_order])
	cv2.imwrite(file_path_sample_data, sample_data)

def generate_pattern_point():
	'''
	Generates a single random point for a pattern.
	'''
	x = random.randrange(symbol_width)
	y = random.randrange(symbol_height)
	return (x, y)

def generate_pattern():
	'''
	Generates a single pattern.
	'''
	points = []
	num_points = random.randrange(min_points_per_pattern, max_points_per_pattern + 1)
	for _ in range(num_points):
		point = generate_pattern_point()
		while point in points:
			point = generate_pattern_point()
		points += [point]
	return points

def generate_patterns():
	'''
	Generates random patterns to overlay over the symbols.
	'''
	for num in range(num_patterns):
		pattern = generate_pattern()
		pattern_text = '\n'.join([f'{point[0]}_{point[1]}' for point in pattern])
		with open(os.path.join(dir_patterns, str(num) + '.pat'), 'w') as file_pattern:
			file_pattern.write(pattern_text)

def main():
	# Clear output directory.
	clear_output_directory()
	# Read the src-image for all the images.
	img_all_symbols = cv2.imread(file_path_all_symbols)
	# Determine the top left pixel for each symbol.
	grid_points = find_grid_points(img_all_symbols)
	# For each symbol extract the cropped image and save it to the output directory.
	for idx in range(len(allowed_symbols)):
		crop_and_save_symbol(img_all_symbols, grid_points, idx)
	# Generate sample_data.png
	generate_sample_data()
	# Generate patterns to obscure the symbols
	generate_patterns()

if __name__ == '__main__':
	main()
