using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lab_3
{
    public class Encryption
    {
        private byte[,] Sblocks = {
                              {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
                              {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
                              {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
                              {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
                              {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
                              {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
                              {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
                              {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1}
                          };

        // Проверка кратности 64 битам исходного текста
        private bool DataMod64(int length)
        {
            if ((length % 8) == 0)
                return true;
            else
                return false;
        }

        // Делаем список из 64-х битных блоков данных
        private List<UInt64> FillListData(string data)
        {
            List<UInt64> resultList = new List<UInt64>();
            byte[] byteText = System.Text.Encoding.GetEncoding(1251).GetBytes(data);

            Array.Reverse(byteText);

            int startIndex = byteText.Length - 8;
            while (startIndex >= 0)
            {
                resultList.Add(BitConverter.ToUInt64(byteText, startIndex));
                startIndex -= 8;
            }

            return resultList;
        }

        // Получаем список из 32-х битных ключей
        private List<UInt32> FillListKey(string key)
        {
            List<UInt32> resultList = new List<UInt32>();
            byte[] byteText = System.Text.Encoding.GetEncoding(1251).GetBytes(key);

            Array.Reverse(byteText);

            // Ключи с 1 по 24
            for (int i = 0; i < 3; i++)
            {
                for (int j = 28; j >= 0; j -= 4)
                    resultList.Add(BitConverter.ToUInt32(byteText, j));
            }

            // Ключи с 24 по 32
            for (int i = 0; i < 32; i += 4)
            {
                resultList.Add(BitConverter.ToUInt32(byteText, i));
            }

            return resultList;
        }

        // Преобразование расшифрованной/зашифрованной строки  
        private string GetPartString(UInt64 partText)
        {
            byte[] byteText = BitConverter.GetBytes(partText);
            Array.Reverse(byteText);
            return System.Text.Encoding.GetEncoding(1251).GetString(byteText);
        }

        // Сложение по модулю 2^32
        private UInt32 Mod_2_32(UInt32 a, UInt32 b)
        {
            UInt32 result = a + b;
            return result;
        }

        // Циключеский сдвиг 32-х битного числа на n разрядов
        private UInt32 ShiftN(UInt32 num, int n)
        {
            UInt32 c = num;
            for (int i = 0; i < n; ++i)
            {
                UInt32 temp = num >> 31;
                num <<= 1;
                num += temp;
            }
            return num;
        }

        // Вычисление старшей части 8-ми байтового блока данных
        private UInt32 PartLeft(UInt64 data)
        {
            data >>= 32;
            UInt32 result = (UInt32)data;//temp;
            return result;
        }

        // Вычисление младшей части 8-ми байтового блока данных
        private UInt32 PartRight(UInt64 data)
        {
            UInt32 result = (UInt32)data;
            return result;
        }

        // Функция f
        private UInt32 Func(UInt32 R, UInt32 Ki)
        {
            UInt32 s = Mod_2_32(R, Ki);
            List<UInt32> partsS = new List<UInt32>();

            for (int i = 0; i < 8; ++i)
            {
                UInt32 temp = s >> 28;
                partsS.Add(temp);
                s <<= 4;
            }

            for (int i = 0; i < 8; ++i)
            {
                partsS[i] = Sblocks[i, (int)partsS[i]];
            }

            s = 0;
            for (int i = 0; i < partsS.Count; ++i)
            {
                s <<= 4;
                s += partsS[i];
            }

            s = ShiftN(s, 11);

            return s;
        }

        // Шифрует 64-х битный блок данных
        private UInt64 EncodePartData(UInt64 partData, List<UInt32> partsKey)
        {
            bool lastRound = false;
            for (int i = 0; i < 32; i++)
            {
                if (i == 31) lastRound = true;
                partData = Feistel(partData, partsKey[i], lastRound);
            }

            UInt64 result = partData;
            return result;
        }

        // Расшифровка 64-х битного блока зашифрованных данных
        private UInt64 DecodePartData(UInt64 partData, List<UInt32> partsKey)
        {
            bool lastRound = false;

            for (int i = 31; i >= 0; i--)
            {
                if (i == 0) lastRound = true;
                partData = Feistel(partData, partsKey[i], lastRound);
            }

            UInt64 result = partData;
            return result;
        }

        // Шаг в сети Фейстеля
        private UInt64 Feistel(UInt64 partData, UInt32 partKey, bool lastRound)
        {
            UInt32 L = PartLeft(partData);
            UInt32 R = PartRight(partData);
            UInt64 result = 0;
            UInt32 temp = Func(R, partKey);
            UInt32 xor = L ^ temp;

            if (lastRound)
            {
                result = (UInt64)xor;
                result <<= 32;
                result += (UInt64)R;
            }
            else
            {
                result = (UInt64)R;
                result <<= 32;
                result += (UInt64)xor;              
            }
            return result;
        }

        // Шифрование
        public string Encoding(string data, string key)
        {
            if (!DataMod64(data.Length))
            {
                while (!DataMod64(data.Length))
                {
                    data += "\0";
                }
            }

            List<UInt32> partsKey = FillListKey(key);
            List<UInt64> partsData = FillListData(data);
            List<UInt64> encodedData = new List<UInt64>();
            string result = "";

            for (int i = 0; i < partsData.Count; ++i)
            {
                encodedData.Add(EncodePartData(partsData[i], partsKey));
            }
            for (int i = 0; i < encodedData.Count; ++i)
            {
                result += GetPartString(encodedData[i]);
            }
            return result;
        }

        // Расшифровка
        public string Decoding(string codedData, string key)
        {
            List<UInt32> partsKey = FillListKey(key);
            List<UInt64> partsData = FillListData(codedData);
            List<UInt64> decodedData = new List<UInt64>();
            string result = "";

            for (int i = 0; i < partsData.Count; ++i)
            {
                decodedData.Add(DecodePartData(partsData[i], partsKey));
            }

            for (int i = 0; i < decodedData.Count; ++i)
            {
                result += GetPartString(decodedData[i]);
            }

            return result;
        }
    }
}