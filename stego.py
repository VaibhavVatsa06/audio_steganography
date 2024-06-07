from pydub import AudioSegment
import numpy as np


def encode_message_in_audio(audio_path, message, output_path):
    # Load audio file
    audio = AudioSegment.from_file(audio_path)
    samples = np.array(audio.get_array_of_samples())

    # Convert message to binary
    message_binary = ''.join(format(ord(char), '08b') for char in message)
    message_length = len(message_binary)

    # Check if the message can fit into the audio
    if message_length > len(samples):
        raise ValueError("Message is too long to fit in the provided audio file.")

    # Encode the message into the audio samples
    encoded_samples = np.copy(samples)


    for i in range(message_length):
            encoded_samples[i] = (samples[i] & ~1) | int(message_binary[i])

    # Create a new audio segment with the encoded samples
            encoded_audio = audio._spawn(encoded_samples)
            encoded_audio.export(output_path, format="wav")
            print(f"Message encoded and saved to {output_path}")


def decode_message_from_audio(encoded_audio_path, message_length):
    # Load encoded audio file
    audio = AudioSegment.from_file(encoded_audio_path)
    samples = np.array(audio.get_array_of_samples())

    # Extract the message from the audio samples
    message_binary = ''
    for i in range(message_length * 8):  # Each character is 8 bits
        message_binary += str(samples[i] & 1)
        # Convert binary message to string
        message = ''
        for i in range(0, len(message_binary), 8):
            byte = message_binary[i:i + 8]
            message += chr(int(byte, 2))

        return message

    # Example usage
    audio_path = "input_audio.wav"
    message = "Secret Message"
    output_path = "encoded_audio.wav"

    # Encode the message
    encode_message_in_audio(audio_path, message, output_path)

    # Decode the message (provide the message length)
    decoded_message = decode_message_from_audio(output_path, len(message))
    print(f"Decoded message: {decoded_message}")