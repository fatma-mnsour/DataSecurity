using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = 0;
            // Loop through each character in the cipher text starting from the third character.
            for (int i = 2; i < cipherText.Length; i++)
            {
                // If the second char of the cipher text matches the current char in plain text,
                // set key equal to the index of that char in plaintext and break out of the loop.
                if (cipherText[1] == plainText[i])
                {

                    key = i;

                    break;

                }
                else if (cipherText[1] == plainText[i - 1])
                {
                    key = i - 1;
                    break;
                }
                else if (cipherText[1] == plainText[i - 2])
                {
                    key = i - 2;
                    break;
                }
                else {
                    continue;
                }

            }

            return key;
        }
    
        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            string PlainText = "";
            double keyy = Convert.ToDouble(key);
            double x = Math.Ceiling((cipherText.Length) / keyy);
             int cols = Convert.ToInt32(x);
            char[,] matrix = new char[key, cols];
            
            int k = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    if (k < cipherText.Length)
                        matrix[i, j] = cipherText[k++];
                    else
                        break; // matrix[i, j] = 'X'; pad the matrix with 'X' if necessary

                }    
            }
            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    PlainText += matrix[j, i];
                   
                }
            }
            Console.WriteLine(PlainText);
            return PlainText;
            
        }

            public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            // Convert key to double for calculation purposes
            double keyyy = Convert.ToDouble(key);

            // Calculate the number of columns needed to fit the plaintext in a grid with 'key' rows
            double x = Math.Ceiling((plainText.Length) / keyyy);
            int cols = Convert.ToInt32(x);
            // Create a nested List of chars to hold the characters in the grid
            var arr = new List<List<char>>();

            // Initialize each row of the nested List
            for (int i = 0; i < key; i++)
            {
                arr.Add(new List<char>());
            }

            // Create a string to hold the ciphertext
            string CipherText = "";

            // Loop through the plaintext and add each character to the appropriate row and column in the grid
            int k = 0;
            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (k < plainText.Length)
                        arr[j].Add(plainText[k++]);
                }
            }

            // Loop through the nested List to print and concatenate the characters in the ciphertext string
            foreach (List<char> row in arr)
            {
                foreach (char c in row)
                {
                    Console.Write(c);
                    CipherText += c;
                }

                Console.Write("\n");
            }

            return CipherText;
            //In this implementation, we first create a nested List of chars with the same dimensions as the 2D char array in the original implementation. We then loop through the plaintext string and add each character to the appropriate List based on the row and column indices. Finally, we loop through the nested List to print and concatenate the characters in the ciphertext string.

            // Note that this implementation assumes that the plaintext string and key are not null and that the key is greater than zero.You may want to add additional error checking or handling for these cases.
        }
    }
}
