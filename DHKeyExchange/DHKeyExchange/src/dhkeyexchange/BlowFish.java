/*
 * Copyright 2012 cbenger.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dhkeyexchange;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class provides the following cryptographic functionalities
 * 
 * 1. Encrypt data using Blowfish
 * 2. Decrypt data using Blowfish
 * 
 * @author cbenger
 */
public final class BlowFish {
    
    private SecretKeySpec key;               //The key for encrypting/decrypting
    private Cipher        encrypt;           //Encryption cipher
    private Cipher        decrypt;           //Decryption cipher
    private final String  TYPE = "Blowfish"; //Encryption method name
    
    /**
     * The encryption key in byte array form
     * @param key the encryption key
     * @throws NoSuchAlgorithmException the specified algorithm wasn't found
     * @throws NoSuchPaddingException 
     * @throws InvalidKeyException the key was invalid
     */
    public BlowFish(byte [] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
        
        this.key = new SecretKeySpec(key,TYPE);
        
        //Creates and initializes the ciphers
        encrypt = Cipher.getInstance(TYPE);
        decrypt = Cipher.getInstance(TYPE);
        
        decrypt.init(Cipher.DECRYPT_MODE,this.key);
        encrypt.init(Cipher.ENCRYPT_MODE,this.key);
    }
    
    /**
     * Encrypts an entire array of data
     * @param data the array to encrypt
     * @return returns the encrypted data
     */
    public byte[] encrypt(byte[] data){
        try {
            return encrypt.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            return null;
        }
    }
    
    /**
     * Decrypted an entire array of data
     * @param data the array to decrypt
     * @return returns the decrypted array
     */
    public byte []decrypt(byte []data){
        try {
            return decrypt.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
           return null;
        }
    }
}
