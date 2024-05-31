from PIL import Image # pip install Pillow
from io import BytesIO
import requests
import re

file_path = 'challenge.png'

def getBlackAndWhiteByChannel(img_path, color_channel):
	'''
	Returns the aztec-code represented encoded in the respective color_channel.
	'''
	color_channel_idx = color_channel.index(255)
	img_combined = Image.open(img_path, mode='r')
	pixels = img_combined.load()
	for row in range(img_combined.size[0]):
		for col in range(img_combined.size[1]):
			pixels[row, col] = (255, 255, 255) if pixels[row, col][color_channel_idx] != 0 else (0, 0, 0)
	return img_combined.convert('1') # convert image to black and white

def getAztecDataFromImage(img_aztec):
	'''
	Returns the data encoded in the img_aztec; decodes the aztec-bar code using the website 'https://zxing.org/w/decode'.
	'''
	# Use BytesIO to get the image-byte data without writing the image to disk.
	buffer = BytesIO()
	img_aztec.save(buffer, 'PNG')
	resp = requests.post('https://zxing.org/w/decode', files={'f': buffer.getvalue()})
	pattern = '<td>Parsed Result</td><td><pre>([^<]*?)</pre>'
	result = re.search(pattern, resp.text)
	return result.group(1)

color_channels = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]
images = [getBlackAndWhiteByChannel(file_path, channel) for channel in color_channels]
flag_parts = [getAztecDataFromImage(image) for image in images]

# Flag:
print(''.join(flag_parts))
