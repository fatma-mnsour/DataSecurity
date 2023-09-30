using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string keystream = string.Empty;
            string key = string.Empty;
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            //keystream_generating loop
            for (int i = 0; i < cipherText.Length; i++)
            {
                keystream += alphabet[((cipherText[i] - plainText[i] + 26) % 97) % 26];
            }
            for (int i = 2; i < keystream.Length; i++)
            {
                if (keystream[i] == keystream[0] && keystream[i + 1] == keystream[1])
                {
                    key = keystream.Remove(i);
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string keystream = string.Empty;
            string decrypted = string.Empty;
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            //keystream_generating loop
            for (int i = 0; i < cipherText.Length; i++)
            {
                keystream += key[i % key.Length];
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                decrypted += alphabet[((cipherText[i] - keystream[i] + 26) % 97) % 26];
            }
            return decrypted;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string keystream = string.Empty;
            string encrypted = string.Empty;
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            plainText = plainText.ToLower();
            key = key.ToLower();

            //keystream_generating loop
            for (int i = 0; i < plainText.Length; i++)
            {
                keystream += key[i % key.Length];
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                encrypted += alphabet[((plainText[i] + keystream[i]) % 97) % 26];
            }
            return encrypted;
        }

    }
}