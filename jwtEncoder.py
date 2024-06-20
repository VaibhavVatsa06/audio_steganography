import jwt
import base64
import hashlib
from pydub import AudioSegment
import numpy as np
from PIL import Image
import os


# Function to encode a message into an image using JWT
def encode_message_in_image_with_jwt(image_path, message, secret, output_path):
    # Create a JWT
    encoded_jwt = jwt.encode({'message': message}, secret, algorithm='HS256')

    # Convert JWT to binary
    jwt_binary = ''.join(format(ord(char), '08b') for char in encoded_jwt)

    # Load image
    image = Image.open(image_path)
    pixels = np.array(image)
    flat_pixels = pixels.flatten()

    # Check if the message can fit into the image
    if len(jwt_binary) > len(flat_pixels):
        raise ValueError("Message is too long to fit in the provided image.")

    # Encode the binary JWT into the image
    for i in range(len(jwt_binary)):
        flat_pixels[i] = (flat_pixels[i] & ~1) | int(jwt_binary[i])

    # Save the modified image
    encoded_image = flat_pixels.reshape(pixels.shape)
    encoded_image = Image.fromarray(encoded_image)
    encoded_image.save(output_path)
    print(f"Message encoded and saved to {output_path}")


# Function to decode a message from an image using JWT
def decode_message_from_image_with_jwt(image_path, secret):
    # Load image
    image = Image.open(image_path)
    pixels = np.array(image)
    flat_pixels = pixels.flatten()

    # Extract the binary JWT from the image
    jwt_binary = ''.join(str(flat_pixels[i] & 1) for i in range(len(flat_pixels)))

    # Convert binary JWT to string
    jwt_str = ''.join(chr(int(jwt_binary[i:i + 8], 2)) for i in range(0, len(jwt_binary), 8))

    # Decode and verify the JWT
    try:
        decoded_jwt = jwt.decode(jwt_str, secret, algorithms=['HS256'])
        return decoded_jwt['message']
    except jwt.InvalidTokenError:
        return "Invalid token"


# Function to encode a message into an audio file using JWT
def encode_message_in_audio_with_jwt(audio_path, message, secret, output_path):
    # Create a JWT
    encoded_jwt = jwt.encode({'message': message}, secret, algorithm='HS256')

    # Convert JWT to binary
    jwt_binary = ''.join(format(ord(char), '08b') for char in encoded_jwt)

    # Load audio file
    audio = AudioSegment.from_file(audio_path)
    samples = np.array(audio.get_array_of_samples())

    # Check if the message can fit into the audio
    if len(jwt_binary) > len(samples):
        raise ValueError("Message is too long to fit in the provided audio file.")

    # Encode the binary JWT into the audio samples
    encoded_samples = np.copy(samples)
    for i in range(len(jwt_binary)):
        encoded_samples[i] = (samples[i] & ~1) | int(jwt_binary[i])

    # Create a new audio segment with the encoded samples
    encoded_audio = audio._spawn(encoded_samples)
    encoded_audio.export(output_path, format="wav")
    print(f"Message encoded and saved to {output_path}")


# Function to decode a message from an audio file using JWT
def decode_message_from_audio_with_jwt(audio_path, secret):
    # Load encoded audio file
    audio = AudioSegment.from_file(audio_path)
    samples = np.array(audio.get_array_of_samples())

    # Extract the binary JWT from the audio samples
    jwt_binary = ''.join(str(samples[i] & 1) for i in range(len(samples)))

    # Convert binary JWT to string
    jwt_str = ''.join(chr(int(jwt_binary[i:i + 8], 2)) for i in range(0, len(jwt_binary), 8))

    # Decode and verify the JWT
    try:
        decoded_jwt = jwt.decode(jwt_str, secret, algorithms=['HS256'])
        return decoded_jwt['message']
    except jwt.InvalidTokenError:
        return "Invalid token"

# Example usage:
# Encode a message into an image
# encode_message_in_image_with_jwt('input_image.jpg', 'Secret Message', 'my_secret_key', 'encoded_image.png')

# Decode a message from an image
# decoded_message = decode_message_from_image_with_jwt('encoded_image.png', 'my_secret_key')
# print(f"Decoded message: {decoded_message}")

# Encode a message into an audio file
# encode_message_in_audio_with_jwt('input_audio.opus', 'hello', 'hola', 'encoded_audio.wav')

# Decode a message from an audio file
decoded_message = decode_message_from_audio_with_jwt('encoded_audio.wav', 'hola')
print(f"Decoded message: {decoded_message}")