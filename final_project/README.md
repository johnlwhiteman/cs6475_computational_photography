
##Overview##

This is a simple digital image Steganography tool that I wrote for my final CS 6475 Computational Photography masters class project at Georgia Institute of Technology. This tool is for academic purposes only and should be used as such.  


##Features##

* Hides and recovers text and images into other images


* Encrypts/Decrypts hidden text using a symmetric (shared secret) key


* Provides integrity checks by embedding the checksums of the hidden text and images into the visible image


##Background##

While my classmates were busy creating works of visual art for their projects, I decided to go the other way. Why not create something that no one can see? That in itself is a visual art. Now any security expert will tell you that hiding or obfuscating something is not a real robust security solution; however, if you add a little cryptography for encryption and decryption along hashing for integrity checks then you are on the right track. I decided to combine these into a python script. I learned many things along way including the importance of bit real estate in an image. 


##Package Dependencies##

* cryptography: https://cryptography.io/en/latest/ (Optional if you want to encrypt text)


##Demo##

I provided a simple demo. You'll see a bunch of windows appear and for each press any key to keep the script going. Performance may vary from system-to-system especially during hidden bit calculations.

	python demo.py

For each window that appears, press any key to 

##Bugs##

Lot's of them...use at your own risk


##Todo##

* Eliminate fixed header locations for checksums and image info and replace with dynamic sizes to support encryption

* Add feature to distribute the hidden bits in pseudo random least significant bit (LSB) locations. The locations can be covered using the same random generator seed provided by Alice to Bob

* Build a better preprocessing for hidden image. Doesn't do a great job now some images

* Add image encryption

* Add asymmetric support

