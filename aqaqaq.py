import hashlib
import os.path
import numpy as np
from Crypto import Cipher
from Cipher import AES
from PIL import Image
from pydub import AudioSegment
import tkinter as tk
from tkinter import filedialog, messagebox, Text, Scrollbar


# Encode class to handle encoding activities in images
class Encode:
    def __init__(self, image_path, password, text_to_encode):
        self.image_path = image_path
        self.password = password.strip()
        self.text_to_encode = text_to_encode.strip()

    def is_password_valid(self):
        if len(self.password) == 0:
            return False
        return True

    def is_text_valid(self):
        if len(self.text_to_encode) == 0:
            return False
        return True

    def is_image_path_valid(self):
        if os.path.exists(self.image_path):
            return True
        return False

    def get_text_binary(self):
        secret_key = hashlib.sha1(str(self.password).encode()).hexdigest()[:32]
        encryption_key = AES.new(secret_key.encode('utf-8'), AES.MODE_EAX, secret_key.encode())
        encrypted_text = encryption_key.encrypt(self.text_to_encode.encode('utf-8'))
        encrypted_text = str(encrypted_text) + "$@&#"
        binary_value = ''.join([format(ord(character), "08b") for character in encrypted_text])
        return binary_value

    def encode_into_image(self):
        try:
            raw_image = Image.open(self.image_path, 'r')
            width, height = raw_image.size
            channels = 3
            if raw_image.mode == 'RGBA':
                channels = 4
            image_array = np.array(list(raw_image.getdata()))
            image_size = image_array.size // channels
            binary_value = self.get_text_binary()
            secret_hash = str(int(hashlib.md5(self.password.encode('utf-8')).hexdigest(), 16))[:5]
            if int(secret_hash) > image_size:
                secret_hash = secret_hash[:4]
                if int(secret_hash) > image_size:
                    secret_hash = secret_hash[:3]
                    if int(secret_hash) > image_size:
                        secret_hash = secret_hash[:2]
                        if int(secret_hash) > image_size:
                            secret_hash = secret_hash[:1]
                            if int(secret_hash) > image_size:
                                return ['Image size is not sufficient to encode the given text.', False]
            text_size = len(binary_value)
            encode_space = image_size - int(secret_hash)
            retro_encode = False
            if text_size > encode_space:
                retro_encode = True
            if text_size > image_array.size:
                return ['Image size is not sufficient to encode the given text.', False]
            else:
                bin_index = 0
                for pixel in range(int(secret_hash), image_size):
                    for channel in range(0, channels):
                        if bin_index < text_size:
                            image_array[pixel, channel] = int(bin(image_array[pixel][channel])[2:9] +
                                                              binary_value[bin_index], 2)
                            bin_index += 1

                if retro_encode:
                    for pixel in range(int(secret_hash)):
                        for channel in range(0, channels):
                            if bin_index < text_size:
                                image_array[pixel, channel] = int(bin(image_array[pixel][channel])[2:9] +
                                                                  binary_value[bin_index], 2)
                                bin_index += 1

                image_array = image_array.reshape(height, width, channels)
                stego_image = Image.fromarray(image_array.astype('uint8'), raw_image.mode)
                return [stego_image, True]
        except Exception as e:
            return [f'Unidentified Error. {e}', False]

    def are_values_valid(self):
        if not self.is_password_valid():
            return ["Password can't be empty.", False]
        elif not self.is_text_valid():
            return ["Text to encode can't be empty.", False]
        elif not self.is_image_path_valid():
            return ["Selected image doesn't exist anymore.", False]
        else:
            return ["Validated", True]


# Decode class to handle decoding activities in images
class Decode:
    def __init__(self, image_path, password):
        self.image_path = image_path
        self.password = password.strip()

    def is_password_valid(self):
        if len(self.password) == 0:
            return False
        return True

    def is_image_path_valid(self):
        if os.path.exists(self.image_path):
            return True
        return False

    def get_decoded_text(self, bytes_string):
        secret_key = hashlib.sha1(str(self.password).encode()).hexdigest()[:32]
        decryption_key = AES.new(secret_key.encode('utf-8'), AES.MODE_EAX, secret_key.encode())
        decrypted_text = decryption_key.decrypt(bytes_string).decode('utf-8', errors='ignore')
        return decrypted_text

    def decode_from_image(self):
        try:
            raw_image = Image.open(self.image_path, 'r')
            image_array = np.array(list(raw_image.getdata()))
            channels = 3
            if raw_image.mode == 'RGBA':
                channels = 4
            image_size = image_array.size // channels
            secret_hash = str(int(hashlib.md5(self.password.encode('utf-8')).hexdigest(), 16))[:5]
            if int(secret_hash) > image_size:
                secret_hash = secret_hash[:4]
                if int(secret_hash) > image_size:
                    secret_hash = secret_hash[:3]
                    if int(secret_hash) > image_size:
                        secret_hash = secret_hash[:2]
                        if int(secret_hash) > image_size:
                            secret_hash = secret_hash[:1]
                            if int(secret_hash) > image_size:
                                return ['Image size is not sufficient to decode the text.', False]
            binary_value = ""
            for pixel in range(int(secret_hash), image_size):
                for channel in range(0, channels):
                    binary_value += (bin(image_array[pixel][channel])[2:][-1])

            for pixel in range(int(secret_hash)):
                for channel in range(0, channels):
                    binary_value += (bin(image_array[pixel][channel])[2:][-1])

            all_bytes = [binary_value[i: i + 8] for i in range(0, len(binary_value), 8)]
            decoded_text = ""
            for byte in all_bytes:
                decoded_text += chr(int(byte, 2))
                if decoded_text[-4:] == "$@&#":
                    break
            decoded_text = decoded_text[:-4]
            decrypted_text = self.get_decoded_text(decoded_text.encode('utf-8'))
            return [decrypted_text, True]
        except Exception as e:
            return [f'Unidentified Error. {e}', False]

    def are_values_valid(self):
        if not self.is_password_valid():
            return ["Password can't be empty.", False]
        elif not self.is_image_path_valid():
            return ["Selected image doesn't exist anymore.", False]
        else:
            return ["Validated", True]


# Audio encoding and decoding functions
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
# audio_path = "input_audio.wav"
# message = "Secret Message"
# output_path = "encoded_audio.wav"

# Encode the message
# encode_message_in_audio(audio_path, message, output_path)

# Decode the message (provide the message length)
# decoded_message = decode_message_from_audio(output_path, len(message))
# print(f"Decoded message: {decoded_message}")

# GUI Application
class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography App")
        self.root.geometry("600x600")

        self.mode = tk.StringVar()
        self.mode.set("Encode")

        self.type = tk.StringVar()
        self.type.set("Image")

        self.file_label = tk.Label(root, text="File Path:")
        self.file_label.pack()
        self.file_entry = tk.Entry(root, width=50)
        self.file_entry.pack()
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack()

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        self.text_label = tk.Label(root, text="Text to Encode:")
        self.text_label.pack()
        self.text_entry = tk.Text(root, height=10, width=50)
        self.text_entry.pack()
        self.scrollbar = Scrollbar(root)
        self.text_entry.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.mode_frame = tk.Frame(root)
        self.mode_frame.pack()
        self.encode_radio = tk.Radiobutton(self.mode_frame, text="Encode", variable=self.mode, value="Encode",
                                           command=self.switch_mode)
        self.encode_radio.pack(side=tk.LEFT)
        self.decode_radio = tk.Radiobutton(self.mode_frame, text="Decode", variable=self.mode, value="Decode",
                                           command=self.switch_mode)
        self.decode_radio.pack(side=tk.LEFT)

        self.type_frame = tk.Frame(root)
        self.type_frame.pack()
        self.image_radio = tk.Radiobutton(self.type_frame, text="Image", variable=self.type, value="Image",
                                          command=self.switch_type)
        self.image_radio.pack(side=tk.LEFT)
        self.audio_radio = tk.Radiobutton(self.type_frame, text="Audio", variable=self.type, value="Audio",
                                          command=self.switch_type)
        self.audio_radio.pack(side=tk.LEFT)

        self.process_button = tk.Button(root, text="Process", command=self.process)
        self.process_button.pack()

    def switch_mode(self):
        if self.mode.get() == "Encode":
            self.text_label.config(text="Text to Encode:")
        else:
            self.text_label.config(text="Extracted Text:")
            self.text_entry.delete(1.0, tk.END)

    def switch_type(self):
        pass

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def process(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()

        if self.type.get() == "Image":
            if self.mode.get() == "Encode":
                text_to_encode = self.text_entry.get(1.0, tk.END).strip()
                encoder = Encode(file_path, password, text_to_encode)
                validation_message, is_valid = encoder.are_values_valid()
                if not is_valid:
                    messagebox.showerror("Error", validation_message)
                    return
                result, success = encoder.encode_into_image()
                if success:
                    save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                             filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
                    if save_path:
                        result.save(save_path)
                        messagebox.showinfo("Success", "Image saved successfully!")
                else:
                    messagebox.showerror("Error", result)
            else:
                decoder = Decode(file_path, password)
                validation_message, is_valid = decoder.are_values_valid()
                if not is_valid:
                    messagebox.showerror("Error", validation_message)
                    return
                result, success = decoder.decode_from_image()
                if success:
                    self.text_entry.delete(1.0, tk.END)
                    self.text_entry.insert(tk.END, result)
                    messagebox.showinfo("Success", "Text decoded successfully!")
                else:
                    messagebox.showerror("Error", result)
        else:
            if self.mode.get() == "Encode":
                text_to_encode = self.text_entry.get(1.0, tk.END).strip()
                output_path = filedialog.asksaveasfilename(defaultextension=".wav",
                                                           filetypes=[("WAV files", "*.wav"), ("All files", "*.*")])
                if output_path:
                    try:
                        encode_message_in_audio(file_path, text_to_encode, output_path)
                        messagebox.showinfo("Success", "Audio saved successfully!")
                    except ValueError as e:
                        messagebox.showerror("Error", str(e))
            else:
                message_length = len(self.text_entry.get(1.0, tk.END).strip())
                try:
                    decoded_message = decode_message_from_audio(file_path, message_length)
                    self.text_entry.delete(1.0, tk.END)
                    self.text_entry.insert(tk.END, decoded_message)
                    messagebox.showinfo("Success", "Text decoded successfully!")
                except ValueError as e:
                    messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
