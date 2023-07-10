# -*- coding: utf-8 -*-

import streamlit as st
import pandas as pd
from io import StringIO
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    return plaintext.decode()



# Setting a page
st.set_page_config(
    page_title = 'Encrytion and Decryption using AES and SHA256',
    page_icon = 'Active',
    #layout = 'wide',
)

# Title the app
st.title('Showcasing Encryption and Decryption using AES ')

st.markdown("""
 * Select Encryption/Decryption from dropbox
 * Select file from system to be encrypted or decryppted
 * Enter Key to encrypt or decrypt data ( use same key for decryption)
 * press Enter key to do the action
 * save the file on your systeem
""")

uploaded_file = None
input_text = None
# #Filter to choose Encryption or Decryption
# if 'key' not in st.session_state:
#     st.session_state.key = ''



#text = st.empty()

def submit():
    print(" i m in submit form")
  

def clear_key():
       #st.session_state["aeskey"] = ""
       None
    
def clear_form():
   print(" i m in clearing form")
   st.session_state["aeskey"] = ""
   
filter = st.selectbox ('Select Encryption or Decryption', 
                           ['Encryption of a file','Decryption of a file'
                            ,'Encryption of a text','Decryption of a text'], 
                           on_change=clear_form)


if filter == 'Encryption of a file':
    uploaded_file = st.file_uploader("Select a file to encrypt", type= ['txt', 'csv'])
elif filter == 'Decryption of a file':
    uploaded_file = st.file_uploader("Select a file to decrypt", type= ['txt', 'csv'])
elif filter == 'Encryption of a text':
    input_text = st.text_input("Input text for encryption", "")
else:
    input_text = st.text_input("Input text for decryption", "")

key = st.text_input("Input AES Key", "", max_chars = 16,  on_change=submit,
                     type ='password', key="aeskey")


if uploaded_file is not None:
    # To read file as bytes:
    bytes_data = uploaded_file.getvalue()
    # To convert to a string based IO:
    stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
    # To read file as string:
    string_data = stringio.read()
    inputagree = st.checkbox('Show content of input file ?')
    # key = st.text_input("Input AES Key", "", max_chars = 16,  on_change=submit,
    #                     type ='password')
    if inputagree == True:
        st.write('Content of a Input file')
        st.write(string_data)
    
    
    if key and key != '':
        hs = hashlib.sha256(key.encode('utf-8')).hexdigest()
        shared_secret_key = bytes.fromhex(hs)
        if filter == 'Encryption of a file' :
            encrypted_data = encrypt_message(string_data, shared_secret_key).hex()
            outputagree = st.checkbox('Show content of output file ?')
            # key = st.text_input("Input AES Key", "", max_chars = 16,  on_change=submit,
            #                     type ='password')
            if outputagree == True:
                st.write('Content of a Output file')
                st.write(encrypted_data)
            
            st.download_button(
                label="Download Encrypted Data as a text file",
                data= encrypted_data,
                file_name='encrypt_data.txt',
                mime='text',
            )
        else :
            try:
                ciphertext = bytes.fromhex(string_data)
                decrypted_data = decrypt_message(ciphertext, shared_secret_key)
                outputagree = st.checkbox('Show content of output file ?')
                # key = st.text_input("Input AES Key", "", max_chars = 16,  on_change=submit,
                #                     type ='password')
                if outputagree == True:
                    st.write('Content of a Output file')
                    st.write(decrypted_data)
                    
                st.download_button(
                    label="Download decrypted Data as a text file",
                    data= decrypted_data,
                    file_name='decrypted_data.txt',
                    mime='text',
                )
            except:
              st.error("Invalid key or encrypted file")
elif input_text is not None and input_text != '':
    #print("key : " + key)
    if key and key != '':
        hs = hashlib.sha256(key.encode('utf-8')).hexdigest()
        shared_secret_key = bytes.fromhex(hs)
        if filter == 'Encryption of a text' :
            encrypted_data = encrypt_message(input_text, shared_secret_key).hex()
            st.write(encrypted_data)
            #clear_key()
        else :
            try:
                ciphertext = bytes.fromhex(input_text)
                decrypted_data = decrypt_message(ciphertext, shared_secret_key)
                st.write(decrypted_data)
            except:
              st.error("Invalid key or encrypted file")
            # finally :
            #     clear_key()
