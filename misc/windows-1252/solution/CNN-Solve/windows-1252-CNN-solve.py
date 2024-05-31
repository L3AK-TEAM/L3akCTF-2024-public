# -*- coding: utf-8 -*-
"""
Created on Fri May 17 08:41:59 2024

@author: Daniel
"""


from PIL import Image
import numpy as np
import random
import string 



# Load the sample image
# This sample data will be used to create the templates
sample_image_path = "C:\\Users\\Daniel\\Desktop\\cap.png"
sample_image = Image.open(sample_image_path).convert('L')  # Convert to grayscale


# Convert the grayscale image to a numpy array
sample_image_np = np.array(sample_image)

# Function to preprocess the image
def preprocess_image(tocheck_image_np):
    # Check the dimensions of the image
    height, width = tocheck_image_np.shape
    assert height == 25, "Height should be 25 pixels."
    assert width % 25 == 0, "Width should be a multiple of 25 pixels."

    # Number of character segments in the image
    num_segments = width // 25

    # Slice the image into 25x25 segments
    character_images = []
    for i in range(num_segments):
        char_image = tocheck_image_np[:, i*25:(i+1)*25]
        # Normalize the image data
        #char_image = char_image.astype('float32') / 255.0
        # Expand dims to add a channel dimension
       #char_image = np.expand_dims(char_image, axis=-1)  # Shape: (25, 25, 1)
        character_images.append(char_image)

    return character_images

# Preprocess the sample image
standardized_images = preprocess_image(sample_image_np)

# Print the length of the list and the shape of the first element
print(f'Number of character segments: {len(standardized_images)}')
print(f'Shape of first character segment: {standardized_images[0].shape}')  # Should print (25, 25, 1)


characters = ['+', 'Æ', 'I', 'Ô', '}', 'Ç', 'à', 'á',
    'C', '%', '>', '@', 'ö', 'ç', '¶', 'Ö', 'ú', 'Õ', '°', 'Ï',
    '¤', 'l', 'Ú', '¸', '³', 't', 'Þ', 'S', '7', '~', 'ª', 'Ø',
    '$', '#', '0', 'g', 'Z', 'ÿ', '·', 'ä', '¾', ',', 'ù', '/',
    'ô', '<', 'L', '«', 'Ó', 'ì', 'v', 'W', '¹', '´', 'Â', 'é',
    'í', ':', 'À', 'J', 'O', '!', 'û', '(', 'E', 'h', '9', 'H',
    'T', 'u', '`', '®', '»', '"', 'º','w',  '¢', ']', 'Í', '§',
    'þ', '5', 'z', 'Ù', 'õ', '÷', 'F', '4', 'e', 'P', 'U', 'K',
    'Á', '¨', 'ê', 'Ñ', '|', 'ã', 'R', '.', 'Ë', 'ý', 'x', 'y',
    'Y', 'X', '£', ';', 'p', 'ë', 'Ê', 'i', 'Ò', 'ï', 'A', '©',
    'Å', 'Î', 'è', 'ó', '_', '\\', 'd', 'k', '^', ')', 'Ü', 'Q',
    '?', 'ò', 'N', 'ü', 'D', 'î', 'G', 'Ì', 'q', 'ß', 'Ý', 'ñ',
    'Ä', 'Û', '3', '¥', 'B', '¬', 'Ã', '¯', 'µ', 'j', '*', '=',
    '1', 'å', "'", '¡', 'c', 'n', 'V', '¦', 'o', 'É', 'a', '¼',
    '6', 'æ', 's', '8', '[', 'Ð', '±', 'b', 'ð', '×', '-', 'â',
    'È', 'r', '{', 'f', 'm', '¿', '²', 'M', 'ø', '&', '2', '½'
    ]
  

def add_noise_kernel(image, kernel_size=1, max_value=40, num_kernels=2):
    noisy_image = np.copy(image)
    height, width = image.shape
    
    for _ in range(num_kernels):
        y = np.random.randint(0, height - kernel_size + 1)
        x = np.random.randint(0, width - kernel_size + 1)
        noise_kernel = np.random.randint(20, max_value + 1, (kernel_size, kernel_size))
        noisy_image[y:y + kernel_size, x:x + kernel_size] = noise_kernel
    
    return noisy_image


## Why white for the shift? i need to peep this
def shift_image(image, shift_pixels=1):
    direction = random.choice(['up', 'down', 'left', 'right'])
    height, width = image.shape
    shifted_image = np.full_like(image, 255)  # Start with a white image

    if direction == 'up':
        shifted_image[:-shift_pixels, :] = image[shift_pixels:, :]
    elif direction == 'down':
        shifted_image[shift_pixels:, :] = image[:-shift_pixels, :]
    elif direction == 'left':
        shifted_image[:, :-shift_pixels] = image[:, shift_pixels:]
    elif direction == 'right':
        shifted_image[:, shift_pixels:] = image[:, :-shift_pixels]
    
    return shifted_image




# Generate noisy images for each standardized character image

noisy_images = []


## Create the training data by adding noise to templates

y = [] # Create targets
for i in range(15,35):
    for z, img in enumerate(standardized_images):
        if characters[z] in set(string.ascii_letters + string.digits):
            num_noisy_images_per_char = 100
        else:
            num_noisy_images_per_char = 700
            
        for _ in range(num_noisy_images_per_char):
            
            noisy_img = add_noise_kernel(img, num_kernels=i)
            noisy_images.append(noisy_img)
            y.append(characters[z])
        
for i in range(1,5):
    for z, img in enumerate(standardized_images):
        shifted_img = shift_image(img, shift_pixels=i)
        noisy_images.append(shifted_img)
        y.append(characters[z])
            
            
targets = y           
            
print(len(targets))

import numpy as np
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.utils import to_categorical

# Create the dictionary mapping characters to integers
char_to_label = {char: idx for idx, char in enumerate(characters)}

# Assuming `noisy_images` is a list of image arrays and `targets` is the corresponding list of character labels

# Convert character labels to integer labels
integer_targets = [char_to_label[char] for char in targets]

# Convert lists to NumPy arrays
X = np.array(noisy_images)
y = np.array(integer_targets)


# Normalize image data to [0, 1]
X = X.astype('float32') / 255.0

# One-hot encode the labels
num_classes = 188  # Number of classes (Windows 1252 characters)
y = to_categorical(y, num_classes)

# Split the data into training and validation sets
X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)


from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout, BatchNormalization
from tensorflow.keras.models import Sequential
from tensorflow.keras.optimizers import Adam


# Define the model
model = Sequential([
    Conv2D(32, (3, 3), activation='relu', input_shape=(25, 25, 1)),
    BatchNormalization(), # Normalizes the inputs to a layer for each mini-batch, stabilizing and speeding up the training process.
    MaxPooling2D((2, 2)), # Reduces the spatial dimensions of the input, making the network more efficient and robust to translations.
    
    Conv2D(64, (3, 3), activation='relu'),
    BatchNormalization(),
    MaxPooling2D((2, 2)),
    
    Flatten(), # Flatten layer converts the 2D feature maps to a 1D feature vector.
    Dense(128, activation='relu'),
    Dropout(0.5), # dropout for regularization.
    Dense(num_classes, activation='softmax')
])

# Summarize the model
model.summary()

# Compile the model
model.compile(optimizer=Adam(learning_rate=0.001), loss='categorical_crossentropy', metrics=['accuracy'])


# Fit(train) the model
history = model.fit(X_train, y_train, batch_size=32, epochs=5, validation_data=(X_val, y_val))


#%%
# Evaluate the model
val_loss, val_accuracy = model.evaluate(X_val, y_val)
print(f"Validation Loss: {val_loss}")
print(f"Validation Accuracy: {val_accuracy}")
# Save the model
#model.save('character_recognition_model.h5')

### Practice solving with a saved image 

# Load the sample image
tocheck_image_path = "C:\\Users\\Daniel\\Desktop\\cap.png"
tocheck_image = Image.open(tocheck_image_path).convert('L')  # Convert to grayscale
# Convert the grayscale image to a numpy array
tocheck_image_np = np.array(tocheck_image)

# Check the dimensions of the image
height, width = tocheck_image_np.shape
assert height == 25, "Height should be 25 pixels."
assert width % 25 == 0, "Width should be a multiple of 25 pixels."

# Number of character segments in the image
num_segments = width // 25

# Slice the image into 25x25 segments
character_images = []
for i in range(num_segments):
    char_image = tocheck_image_np[:, i*25:(i+1)*25]
    character_images.append(char_image)

# Convert standardized images to numpy array and normalize
standardized_images_np = np.array(character_images).astype('float32') / 255.0
standardized_images_np = np.expand_dims(standardized_images_np, axis=-1)

### Make predictions


# Predict the characters
predictions = model.predict(standardized_images_np)
predicted_labels = np.argmax(predictions, axis=1)

# Map the integer labels back to characters
label_to_char = {idx: char for char, idx in char_to_label.items()}
recognized_characters = [label_to_char[label] for label in predicted_labels]

# Print the recognized characters
print("Recognized characters: ", ''.join(recognized_characters))

#%%

import base64
import cv2
# Function to decode base64 image
def decode_base64_image(base64_str):
    img_data = base64.b64decode(base64_str)
    img_array = np.frombuffer(img_data, np.uint8)
    img = cv2.imdecode(img_array, cv2.IMREAD_GRAYSCALE)
    return img

# Function to preprocess the image and prepare it for the model
def preprocess_image(img):
    height, width = img.shape
    assert height == 25, "Height should be 25 pixels."
    assert width % 25 == 0, "Width should be a multiple of 25 pixels."
    
    num_segments = width // 25
    character_images = [img[:, i*25:(i+1)*25] for i in range(num_segments)]
    
    standardized_images_np = np.array(character_images).astype('float32') / 255.0
    standardized_images_np = np.expand_dims(standardized_images_np, axis=-1)
    return standardized_images_np

# Function to predict characters from the processed images
def predict_characters(images):
    predictions = model.predict(images)
    predicted_labels = np.argmax(predictions, axis=1)
    label_to_char = {idx: char for char, idx in char_to_label.items()}
    recognized_characters = [label_to_char[label] for label in predicted_labels]
    return ''.join(recognized_characters)

from pwn import *

# Function to connect to the server and solve the challenge
def connect_to_server(host, port):
    r = remote(host, port)
    
    try:
        print(r.recvuntil(b"Enter anything else to exit immediately.").decode())
        r.sendline(b'1')
        print("Sent: 1")
        
        for _ in range(102):  # Loop to handle multiple interactions
            response = r.recvline().decode().strip()
            print(f"Received: {response}")

            if "Captcha" in response:
                # Extract base64 string from the response
                base64_str = response.split(':')[-1].strip()
                img = decode_base64_image(base64_str)
                processed_images = preprocess_image(img)
                recognized_characters = predict_characters(processed_images)
                z = [format(ord(x), "x") for x in recognized_characters]
                f = ''
                for thing in z:
                    f+=thing
                
                print(f)

                r.sendline(f.encode())
                print(f"Sent: {f}")
                print(recognized_characters)
            else:
                print("No captcha found in response")
        
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        r.close()
        print("Connection closed")

# Example usage
host = "35.229.44.203"
port = 6666
import time

start_time = time.time()
connect_to_server(host, port)
end_time = time.time()
elapsed_time = end_time - start_time

print(f"Elapsed time: {elapsed_time} seconds")                    
