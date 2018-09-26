from PIL import Image
import numpy as np

img = (np.array(Image.open("Stego.png"))[:,:,2]&1).reshape(-1,8).tolist()
idx = ''.join([chr(int(''.join(list(map(str,i))),2)) for i in img]).find('CS 2018 Fall')
data = b''.join([int(''.join(list(map(str,i))),2).to_bytes(1,byteorder='big') for i in img])
open('Stego','wb').write(data)
