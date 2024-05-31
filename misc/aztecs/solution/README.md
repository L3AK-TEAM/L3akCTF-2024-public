# L3ak CTF 2024
Competition URL: https://ctf.l3ak.team/
## Overview

| Challenge | Category | Points | Solves | Flag                                        |
| --------- | -------- | ------ | ------ | ------------------------------------------- |
| Aztecs    | misc     |  392   |   50   | L3AK{d0_YOu_r34L1y_ThINk_7H3_aNCi3n7_4z7Ec5_kn3W_B4rc0De5} |

## Challenge Author:
- [Matthias](https://github.com/0x-Matthias/)

## Writeup Author
- [Matthias](https://github.com/0x-Matthias/)

## Challenge: Aztecs
Who invented this modern technology?

## Attachments
- challenge.png: ![challenge.png](../dist/challenge.png)
- [solver.py](./solver.py)

## Inspipration

This challenge was inspired by a combination of `Aztec` barcodes and `High Capacity Colored 2-Dimensional (HCC2D) QR Codes`.

## Solution

As hinted to by the challenge title and the inspiration, the `challenge.png` is actually a composition of three Aztec barcodes - with the three separate barcodes being hidden in the three color channels of the image.

To solve the challenge, first you need to split the image into three `Aztec` barcodes - one for each color channel of the image and turn them into black & white images:
```python
from PIL import Image # pip install Pillow

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

file_path = 'challenge.png'
color_channels = [(255, 0, 0), (0, 255, 0), (0, 0, 255)]
images = [getBlackAndWhiteByChannel(file_path, channel) for channel in color_channels]
```

Afterwards you can decode the separate `Aztec` barcodes using any decoder. For simplicity's sake, you can choose to use an online decoder, that you can automate quite easily:
```python
from io import BytesIO
import requests
import re

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

flag_parts = [getAztecDataFromImage(image) for image in images]
```

Turns out, the separate `Aztec` barcodes contain parts of the final flag; so you only need to assemble the flag using
```python
print(''.join(flag_parts))
```

and you will be greeted by the flag: `L3AK{d0_YOu_r34L1y_ThINk_7H3_aNCi3n7_4z7Ec5_kn3W_B4rc0De5}`


## Resources
- [Wikipedia: Aztec Code](https://en.wikipedia.org/wiki/Aztec_Code)
- [Wikipedia: Barcode (Matrix (2D) codes)](https://en.wikipedia.org/wiki/Barcode#Matrix_(2D)_codes)
- [Wikipedia: QR code (High Capacity Colored 2-Dimensional (HCC2D) Code)](https://en.wikipedia.org/wiki/QR_code#HCC2D)
- [Wikipedia: High Capacity Color Barcode](https://en.wikipedia.org/wiki/High_Capacity_Color_Barcode)

### Decoders
- [ZXing Decoder Online](https://zxing.org/w/decode.jspx)
- [Dynamsoft Barcode Reader](https://www.dynamsoft.com/barcode-reader/barcode-types/aztec-code/)