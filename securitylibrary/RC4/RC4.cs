using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            int flag = 0;
            if (key.StartsWith("0x"))
            {
                (key, cipherText) = (ChckInput(key), ChckInput(cipherText));
                flag = 1;
            }
            int idx = 0;
            int[] S = new int[256];
            char[] T = new char[256];
            string plainText = "";
            int keyLength = key.Length;
            
            int i = 0;
            while (i < 256)
            {
                S[i] = i;
                if (idx >= keyLength)
                    idx -= keyLength;

                T[i] = key[idx];
                idx++;
                i++;
            }


            int j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                (S[i], S[j]) = (S[j], S[i]);
            }
            //Generate the Key stream K
            int x = 0, y = 0;
            int cipherLength = cipherText.Length;
            int[] newKey = new int[cipherLength];
            int ind = 0;
            int temp;
            while (cipherLength > 0)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                (S[x], S[y]) = (S[y], S[x]);
                temp = (S[x] + S[y]) % 256;
                newKey[ind++] = S[temp];
                cipherLength--;
            }

            //Decrypt XOR with K
         
            for (i = 0; i < newKey.Length; i++)
            {
                int xorResult = newKey[i] ^ (int)cipherText[i];
                char c = (char)xorResult;
                plainText += c;
            }

            // If flag is equal to 1, call the stringToHex method to convert plainText to a hexadecimal string

            plainText = flag == 1 ? stringToHexa(plainText) : plainText;

            return plainText;
        }
        public override string Encrypt(string plainText, string key)
        {
            //check if the input is hexa
           
            int flag = 0;
            if (key.StartsWith("0x"))
            {
                flag = 1;
                (key, plainText) = (ChckInput(key), ChckInput(plainText));
            }
            // Initialize  S and T
           
            int idx = 0;
            string cipherText = "";
            int KeyLen = key.Length;
            int[] S = Enumerable.Repeat(0, 256).ToArray();
            char[] T = Enumerable.Repeat('\0', 256).ToArray();


            int i = 0;
            while (i < 256)
            {
                S[i] = i;
                if (idx >= KeyLen)
                    idx -= KeyLen;

                T[i] = key[idx];
                idx++;
                i++;
            }

            //initial permutation of S
            int j = 0;
            for ( i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                (S[i], S[j]) = (S[j], S[i]);
            }
            //generate of Key stream K
            int x = 0, y = 0;
            int plainLength = plainText.Length;
            int[] NewKey = new int[plainLength];
            int ind = 0;
            int temp;
           
            while (plainLength > 0)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                swap(S, x, y);
                 temp = (S[x] + S[y]) % 256;
                NewKey[ind] = S[temp];
                ind++;
                plainLength--;
            }
            //Decrypt XOR with K
            for ( i = 0; i < plainText.Length; i++)
            {
                int XorResult = NewKey[i] ^ (int)plainText[i];
                char ch = (char)XorResult;
                cipherText += ch;
            }
            // if flag is equal to 1, convert cipherText to a hexadecimal string
            // using the stringToHex function, and assign the result to cipherText.
            // otherwise,,, assign cipherText to cipherText.

            cipherText = flag == 1 ? stringToHexa(cipherText) : cipherText;

            return cipherText;
        }
        string stringToHexa(string str)
        {
           
            string res = "0x";
            int i = 0;
            while (i < str.Length)
            {
                byte b = Convert.ToByte(str[i]);
                String hexa = b.ToString("x");
                res += hexa;
                i++;
            }
            return res;
        }
        void swap(int[] arr, int i1, int i2)
        {
            (arr[i1], arr[i2]) = (arr[i2], arr[i1]);
        }
        public string ChckInput(string input)
        {
            byte[] result = Array.Empty<byte>();
            string txt = "";
            // Remove the "0x" prefix from the input string if it exists
            input = input.Remove(0, input.StartsWith("0x") ? 2 : 0);

             result = new byte[input.Length >> 1];

            int count = 0;
            int i = 0;
            while (i < input.Length)
            {
                result[count] = Convert.ToByte(input[i].ToString() + input[i + 1].ToString(), 16);
                count++;
                i += 2;
            }
            char[] chars = new char[result.Length];
            for ( i = 0; i < result.Length; i++)
            {
                chars[i] = (char)result[i];
            }
             txt = new string(chars);

            return txt;
        }
        
    }
}