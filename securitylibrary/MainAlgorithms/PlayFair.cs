using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string PlainText = "";
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            cipherText = cipherText.Replace('j', 'i');
            
            string chars = "abcdefghijklmnopqrstuvwxyz";
            string x = key + chars;
           
            x = x.Replace('j', 'i');
            string unique = new string(x.Distinct().ToArray()); //unique array values
            char[,] array = new char[5, 5];

            //key matrix
            int indx = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int colmn = 0; colmn < 5; colmn++)
                {
                    array[row, colmn] = unique[indx];
                    indx++;
                }
            }


            // encrypt

            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                int first_letter_row = 0, first_letter_col = 0, sec_letter_row = 0, second_letter_col = 0;
                int count = 0;


                for (int row = 0; row < 5; row++)
                {
                    for (int colmn = 0; colmn < 5; colmn++)
                    {
                        if (cipherText[i] == array[row, colmn])
                        {
                            first_letter_row = row;
                            first_letter_col = colmn;
                            count++;
                        }
                        else if (cipherText[i + 1] == array[row, colmn])
                        {
                            sec_letter_row = row;
                            second_letter_col = colmn;
                            count++;
                        }
                        else
                        { 
                            continue;
                        }


                    }
                   
                }
                //in the same row
                if (first_letter_row == sec_letter_row)
                {
                    int row_num = 0, col_num = 0;
                   
                    if (first_letter_col == 0)
                    {
                        first_letter_col = 4;
                        PlainText += array[first_letter_row, first_letter_col];
                        row_num += 1;
                    }
                      else if (row_num == 0)
                    {
                        PlainText += array[first_letter_row, (first_letter_col - 1)];
                        
                    }
                    else
                    {
                        continue;
                    }
                     if (second_letter_col == 0)
                    {
                        second_letter_col = 4;
                        PlainText += array[sec_letter_row, second_letter_col];
                        col_num += 1;
                    }

                    else if (col_num == 0)
                    {
                        PlainText += array[sec_letter_row, (second_letter_col - 1)];
                    }
                    else
                    {
                        continue;
                    }
                }


                else if (first_letter_col == second_letter_col)
                {
                    int row_num = 0, col_num = 0;
                    if (first_letter_row == 0)
                    {
                        first_letter_row = 4;
                        PlainText += array[first_letter_row, first_letter_col];
                        row_num += 1;

                    }
                    else if (row_num == 0)
                    {
                        PlainText += array[(first_letter_row - 1), first_letter_col];
                    }
                    else
                    {
                        continue;
                    }
                    if (sec_letter_row == 0)
                    {
                        sec_letter_row = 4;
                        PlainText += array[sec_letter_row, second_letter_col];
                        col_num += 1;
                    }

                    else if (col_num == 0)
                    {
                        PlainText += array[(sec_letter_row - 1), second_letter_col];
                    }
                    else 
                    {
                        continue; 
                    }
                }

                else
                {
                    PlainText += array[first_letter_row, second_letter_col];
                    PlainText += array[sec_letter_row, first_letter_col];
                    continue;
                }
            }
            int c = 0;

            string result = PlainText;
            
            for (int i = 0; i < PlainText.Length - 1; i++)
                if (PlainText[i] == 'x'&& (i + 1) % 2 == 0 )
                {
                    if (PlainText[i - 1] == PlainText[i + 1])
                    {
                        result = result.Remove(i - c,1);
                        c++;
                       
                    }
                    else
                    {
                        continue;
                    }

                }

            else if (result[result.Length - 1] == 'x')
            {
                result = result.Remove(result.Length - 1);
               
            }
           
           
            Console.WriteLine(result);

            return result.ToUpper();
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            string cipherText = "";
            key = key.ToLower();
            plainText = plainText.ToLower();

           

            string chars = "abcdefghijklmnopqrstuvwxyz";

            string x = key + chars;
            
            x = x.Replace('j', 'i'); //Returns a new string in which all occurrences of a specified Unicode character in this instance are replaced with another specified Unicode character.
            string unique = new string(x.Distinct().ToArray()); // unique array elements

            char[,] array = new char[5, 5];

            int index = 0;


            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    array[row, col] = unique[index];
                    index++;
                }
            }


    


            for (int i = 0; i < plainText.Length - 1; i += 2)
            {

                if (plainText[i] == plainText[i + 1])   //when AA so AX -- A new string that is equivalent to this instance, but with value inserted at position startIndex.
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }

            if (plainText.Length % 2 != 0) //when you have A only so  make it AX "when even matrix, when key is even"
            {
                plainText = plainText + 'x';
            }

            for (int i = 0; i < plainText.Length - 1; i += 2) //deal with msg 2letters
            {
                int first_row_letter = 0;
                int sec_row_letter = 0;
                int first_col_letter = 0;
                int sec_col_letter = 0;
                int counter = 0;

                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (plainText[i] == array[row, col])
                        {
                            first_row_letter = row;
                            first_col_letter = col;
                            counter++;
                        }
                        else if (plainText[i + 1] == array[row, col])
                        {
                            sec_row_letter = row;
                            sec_col_letter = col;
                            counter++;
                        }
                        else
                        {
                            continue;
                        }
                        

                    }
                   

                }
                //same rows
                if (first_row_letter == sec_row_letter)
                {
                    cipherText += array[first_row_letter, ((first_col_letter + 1) % 5)];
                    cipherText += array[sec_row_letter, ((sec_col_letter + 1) % 5)];
                }
                else if (first_col_letter == sec_col_letter) //same coulms
                {
                    cipherText += array[((first_row_letter + 1) % 5), first_col_letter];
                    cipherText += array[((sec_row_letter + 1) % 5), sec_col_letter];
                }
                else
                {
                    cipherText += array[first_row_letter, sec_col_letter];
                    cipherText += array[sec_row_letter, first_col_letter];
                    continue;
                }


            }

            Console.WriteLine(cipherText.ToUpper(),"\n");

            return cipherText.ToUpper();
           
        }
    }
}