using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText.ToLower();
            cipherText = cipherText.ToLower();
            int row = 0;
            int column = 0;



            // Find length of key
            int count = 2;
            while (count < 8)
            {
                if (plainText.Length % count == 0)
                    column = count;
                count++;
            }
            // Create 2D array to hold transposed ciphertext and plain text
            row = plainText.Length / column;
            char[,] transposed = new char[row, column];
            char[,] ptransposed = new char[row, column];


            // Transpose plaintext into 2D array
            int counter = 0;
            int i = 0;
            while (i < row)
            {
                for (int j = 0; j < column; j++)
                {
                    if (counter < plainText.Length)
                    {
                        ptransposed[i, j] = plainText[counter];
                        counter++;
                    }

                }
                i++;
            }
            // Transpose ciphertext into 2D array
            int index = 0;
            int x = 0;
            while (x < column)
            {
                for (int j = 0; j < row; j++)
                {
                    if (index < plainText.Length)
                    {

                        transposed[j, x] = cipherText[index];
                        index++;
                    }
                }
                x++;
            }
            // Identify key characters from transposed array

            List<int> key = new List<int>(column);
            for (int c = 0; c < column; c++)
            { // Calculate frequency
                int freqDist = 0;
                for (int k = 0; k < column; k++)
                {
                    for (int j = 0; j < row; j++)
                    {
                        Char p = ptransposed[j, c];
                        char t = transposed[j, k];
                        if (p == t)
                        {
                            freqDist++;
                        }
                        if (freqDist == row)
                            key.Add(k + 1); //+1 key base 1, index in cipher and plain base 0.
                    }
                    freqDist = 0;
                }
            }
            //  not Adding character to the key
            if (key.Count == 0)
            {
                for (int z = 0; z < column + 2; z++)
                {
                    key.Add(0);
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            // Calculate the number of rows in the grid
            int numRows = (int)Math.Ceiling((double)cipherText.Length / key.Count);

            // Create a 2D array to hold the characters in the grid
            char[,] grid = new char[numRows, key.Count];

            // Create a dictionary to map the column indexes to their corresponding key values
            Dictionary<int, int> keyDictionary = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                keyDictionary.Add(key[i] - 1, i);
            }

            // Fill the grid with the ciphertext in row-major order
            int currIndex = 0;
            int numColumns = cipherText.Length % key.Count;
            for (int rowIndex = 0; rowIndex < key.Count; rowIndex++)
            {
                for (int colIndex = 0; colIndex < numRows && currIndex < cipherText.Length; colIndex++)
                {
                    if (numColumns != 0 && colIndex == numRows - 1 && keyDictionary[rowIndex] >= numColumns)//remove the x if it is in the last entry
                        continue;
                    grid[colIndex, keyDictionary[rowIndex]] = cipherText[currIndex++];//put letters in column with index 0.1.2.... 
                }
            }

            // Build the plaintext by reading columns of the grid in key order
            StringBuilder plaintextBuilder = new StringBuilder();
            // foreach (int keyVal in key)
            for (int rowIndex = 0; rowIndex < numRows; rowIndex++)
            {
                // int colIndex = keyDictionary[keyVal - 1];

                for (int colIndex = 0; colIndex < key.Count; colIndex++)
                {
                    if (grid[rowIndex, colIndex] != 'x') // skip any extra padding Xs added during encryption
                    {
                        plaintextBuilder.Append(grid[rowIndex, colIndex]);//get letters from the rows
                    }
                }
            }

            return plaintextBuilder.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int numRows = (int)Math.Ceiling((double)plainText.Length / key.Count);
            char[,] grid = new char[numRows, key.Count];
            Dictionary<int, int> keyDictionary = new Dictionary<int, int>();
            int currIndex = 0;
            int i = 0;
            while (i < key.Count)
            {
                keyDictionary.Add(key[i] - 1, i);
                i++;
            }
            // Fill the grid with the plaintext in column-major order
            for (int col = 0; col < numRows; col++)
            {
                // int numChars = key[col];
                for (int row = 0; row < key.Count && currIndex < plainText.Length; row++)

                {
                    if (currIndex >= plainText.Length)//put x to fill the empty rows
                    {
                        grid[col, row] = 'x';
                        //currIndex++;
                        //int lenght=plainText.Length;
                        //lenght++;
                    }
                    else
                    {
                        grid[col, row] = plainText[currIndex++];//*
                        //currIndex++;
                    }
                }
            }


            // Build the ciphertext by reading rows of the grid in key order
            StringBuilder ciphertextBuilder = new StringBuilder();
            for (int colIndex = 0; colIndex < key.Count; colIndex++)
            {

                // int colIndex = key.IndexOf(keyVal);

                for (int rowIndex = 0; rowIndex < numRows; rowIndex++)
                {

                    ciphertextBuilder.Append(grid[rowIndex, keyDictionary[colIndex]]);//*

                }
            }

            return ciphertextBuilder.ToString();
        }
    }
}
