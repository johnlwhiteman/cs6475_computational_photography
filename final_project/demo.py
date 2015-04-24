import cv2
import numpy as np
import sys
from StegaBits import *
    
def show_demo():
    visible_image_path = "demo_visible.png"
    hidden_image_path = "demo_hidden.png"
    output_image_path = "demo_results.png"
    seed = None
    shared_secret_key = None
    alice_text = "Dr. Irfan Essa will be the next James Bond!"
    alice_text_checksum = hashlib.sha256(alice_text).hexdigest() 

    try:
        from cryptography.fernet import Fernet
        shared_secret_key =  Fernet.generate_key()
    except Exception:
        pass

    print("Alice is working")
    alice = StegaBits(visible_image_path, shared_secret_key, seed)
    alice.hide(alice_text, hidden_image_path)
    alice.save(output_image_path)
    alice_image_checksum = alice.get_image_checksum()
    cv2.imshow("Alice's Unmodified Image", cv2.imread(visible_image_path))
    cv2.waitKey(0)
    cv2.imshow("Alice's Unmodified Hidden Image", cv2.imread(hidden_image_path))
    cv2.waitKey(0)
    print("Alice's secret message: %s" %(alice_text))
    cv2.imshow("Alice's Modified Image", alice.image)
    cv2.waitKey(0)
    
    print("Bob is working")
    bob = StegaBits(output_image_path, shared_secret_key, seed)
    bob_text = bob.get_text()
    bob_encrypted_text = bob.get_text(dont_decrypt=True)
    bob_text_info = bob.get_text_info()
    bob_text_checksum = bob.get_text_checksum()
    bob_image = bob.get_image()
    bob_image_info = bob.get_image_info()
    bob_image_checksum = bob.get_image_checksum()
    bob.show("Bob's Received Modified Image")
    print """
Text:
  Alice: %s   
  Bob:   %s
    
Text Checksum:
  Alice: %s
  Bob:   %s
    
Image Checksum:
  Alice: %s
  Bob:   %s

Image Details:
  Width:  %s
  Height: %s
  Offset: %s
  Seed:   %s
  
Text Details:
  Length: %s
  Offset: %s
  
Cryptography:
  Key:       %s
  Encrypted: %s
""" %(alice_text, bob_text, alice_text_checksum, bob_text_checksum, 
      alice_image_checksum, bob_image_checksum,
      bob_image_info['width'], bob_image_info['height'],
      bob_image_info['offset'], bob_image_info['seed'],
      bob_text_info['length'], bob_text_info['offset'],
      shared_secret_key, bob_encrypted_text)      
    bob.show_image("Bob's Extracted Hidden Image")
    bob.show_images("Bob's Shows a Montage")
    
if __name__ == "__main__":
    show_demo()



