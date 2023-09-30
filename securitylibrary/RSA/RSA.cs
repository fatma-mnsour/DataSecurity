using System;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        // function to calc power and mod num
        public static int ModPower(int num, int pow, int mod)
        {
            int res = 1;
            int i = 1;
            while (i <= pow)
            {
                res = (res * num) % mod;
                i++;
            }
            return res;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int product = p * q;
            int encryptedMessage = ModPower(M, e, product);  // Call ModPower to encrypt the message using the public key (e, product)
            return encryptedMessage; // Return the encrypted message
        }
        public int Decrypt(int p, int q, int C, int e)
        {
           
            int modulus = p * q;  // Calculate the modulus (product of p and q)
            int totient = (p - 1) * (q - 1);  // Calculate the totient of the modulus
            int decryptionKey = new ExtendedEuclid().GetMultiplicativeInverse(e, totient);// Calculate the decryption key using the Extended Euclidean algorithm
            int decryptedMessage = ModPower(C, decryptionKey, modulus);// Call ModPower to decrypt the message using the private key (decryptionKey, modulus)
            return decryptedMessage; // Return the decrypted message

        }
    }

}