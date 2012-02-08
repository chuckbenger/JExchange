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

import java.math.BigInteger;
import java.util.Random;

/**
 * DHKeyExchange provides the following functionalities using the 
 * Diffie–Hellman key exchange method.
 * 
 * 1. Generating prime numbers
 * 2. Generating a secret key
 * 3. Computing the public key
 * 4. Computing the private key given a public key
 * 
 * More information can be found at http://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
 * @author cbenger
 */
public class DHKeyExchange {

   /*Instance vairables*/
   private long   prime;     //The prime number
   private byte   base;      //The base number
   private int    secret;    //Generated secret number
   private long   publicKey; //Public key computed and given to other host
   private long   privateKey;//Private key calculated from public key
   private Random random;    //Used to generate random numbers
   
   /*Constansts*/
   private final byte SIGN_BIT = 1;//Bit used for representing negative numbers

   
   /**
    * Constructor for DHKeyExchange initializes the random generator
    */
   public DHKeyExchange(){
       random = new Random(System.nanoTime());
   }
    
   /**
    * Computes the initial prime,base and secret keys
    */
    public void computeKeys(){
       prime = generatePrime();
       base = generateBase();
       secret = generateSecret();
       computePublic();
    }
    
    /**
     * Computes the public key
     */
    private void computePublic(){
        publicKey = (long)(Math.pow(base, secret) % prime);
    }
    
    /**
     * Generates a prime number
     * @return returns the prime number
     */
    private long generatePrime(){
        return BigInteger.probablePrime(Long.SIZE - SIGN_BIT, random).longValue();
    }
    
    /**
     * Generates a small base prime number
     * @return returns a small base prime number
     */
    private byte generateBase(){
        final byte BIT_REDUCTION = 4 + SIGN_BIT;
        return BigInteger.probablePrime(Byte.SIZE - BIT_REDUCTION, random).byteValue();
    }
    
    /**
     * Generates a secret key
     * @return returns the secret key
     */
    private int generateSecret(){
        final byte MIN = 1;
        final byte MAX = 10;
        return MIN + Math.abs(random.nextInt() % MAX);
    }
    
    /**
     * Computes the private key
     * @param publicKey the public key to compute private key from
     */
    public void computePrivate(long publicKey){
        privateKey = (long) (Math.pow(publicKey, secret) % prime);
    }

    /**
     * Sets the prime and base number
     * @param prime the prime number
     * @param base the base number
     */
    public void setData(long prime, byte base){
        this.prime = prime;
        this.base = base;
        secret = generateSecret();
        computePublic();
    }
    
    /**
     * Gets the base number
     * @return returns the base number
     */
    public byte getG() {
        return base;
    }

    /**
     * Gets the prime number
     * @return returns the prime number
     */
    public long getP() {
        return prime;
    }
    
    /**
     * Gets the public key
     * @return returns the public key
     */
    public long getPublicKey() {
        return publicKey;
    }
    
    /**
     * Gets the byte array of the private key
     * @return returns an array containing the private key
     */
    public byte[] getPrivateKey(){
        byte[] key = new byte[Long.SIZE / 8];
        
        for(int i = 0; i < key.length; i++)
            key[i] = (byte) ((privateKey >> i * 8) & 0xFF);
        return key;
    }
}
