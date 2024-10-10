!!: This program is not fitted for professional use in security!

# Warning
- This project is not completed yet and is only to be viewed as a general idea of the actual program itself.
- The program itself is not compilable yet, as it is still in development.
- Although the idea of storing your password into a png is pretty neat, it is not recommended as an actual security layer
  - This project is a sort of proof of concept

# What is Steganography?
Steganography is a method of hiding information into a data of a photo. It takes advantage of the Least Significant Bit (LSB) of a pixel.

Example: Suppose a pixel is represented by 8 bits. 
The last bit is the LSB and switching this bit into the opposite value wouldn't make as much of a difference so that it would be impossible for the human eye to detect any difference.
With this information in mind, one could convert a plain text data into its binary form and distribute each of the bits into pixels, which "hides the data in a photo".
Theoretically, one could even hide a whole malware into a photo, which could be a potential attack trajectory.

# Purpose
Randsteg is a program that hides your encrypted password into a png file.
Its name is short for RANDomized STEGanography.

The general idea: you can hide your data into a png file by using bit operations on to the pixels of an image. 

# Why use Randsteg? (TLDR)
Randsteg will:
1. hide your encrypted password (via aes-cbc with a masterkey) and not the password itself
2. hide individual bits of the ciphertext into cryptographically secure randomized coordinates of pixels throughout the png file
3. only log the encrypted coordinates and not the ciphertext, which will be used for decryption (along side with an encrypted filepath of the png, id of the password, length of ciphertext and more stuff for necessary logging)
4. turn your png of your puppy into a password storage (which is pretty neat)

# Detailed Procedure
1. Stegnography is detectable, if for example a program writes the individual pixels into a field of pixels that have the same set of bits, in other words, have the same color. To prevent this issue, this program will distribute the bits of the input data into randomized coordinates of a photo
  - For the randomized coordinates, a CSPRNG (Cryptographically Secure Pseudorandom Number Generator) from Openssl lib is used, which makes it hard to replicate the results
2. The coordinates will then be encrypted with the masterkey and stored into a log file, which keeps track of the necessary information to extract the input data out of the png file.
  - This doesn't prevent the issue of the target bits to be potentially detected.
  - However, it would be hard for a detection program to make sense out of the extracted bits, as they will be randomly distributed throughout the png file and the only way to keep the order of the bits is to crack the hash in the log file or bruteforcing combinations of the bits.
3. Alongside the coordinates, information like:
  - id for password so you can navigate through multiple passwords
  - hashing algorithm id (for now, only aes-cbc exists)
  - encrypted filepath of the png the password is hid in (with its string length)
  - encrypted coordinates of the pixels where the bits of the hashed passwords are distributed to (with its string length)
  - maximum amount of digits that the largest number between the width and height of the png file has (so if 500 x 1920px = 4 digits)
  will be stored

The decryption process will:
1. try to decrypt the coordinates and filepath with the masterkey
2. extract the least significant bits of the pixels regarding the coordinates
3. combine the extracted bits and reproduce the encrypted password
4. decrypt the password with a masterkey
