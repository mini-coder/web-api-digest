﻿
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace DigestDemo.Secutiry
{
    /// <summary>
    /// 字符串Hash操作类
    /// </summary>
    public static class HashHelper
    {
        /// <summary>
        /// 获取字符串的MD5哈希值
        /// </summary>
        public static string GetMD5(string value, Encoding encoding = null)
        {
            
            if (encoding == null)
            {
                encoding = Encoding.ASCII;
            }
            byte[] bytes = encoding.GetBytes(value);
            return GetMD5(bytes);
        }

        /// <summary>
        /// 获取字节数组的MD5哈希值
        /// </summary>
        public static string GetMD5(byte[] bytes)
        {
            
            StringBuilder sb = new StringBuilder();
            MD5 hash = new MD5CryptoServiceProvider();
            bytes = hash.ComputeHash(bytes);
            foreach (byte b in bytes)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 获取字符串的SHA1哈希值
        /// </summary>
        public static string GetSHA1(string value)
        {
            StringBuilder sb = new StringBuilder();
            SHA1Managed hash = new SHA1Managed();
            byte[] bytes = hash.ComputeHash(Encoding.ASCII.GetBytes(value));
            foreach (byte b in bytes)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 获取字符串的Sha256哈希值
        /// </summary>
        public static string GetSHA256(string value)
        {
            

            StringBuilder sb = new StringBuilder();
            SHA256Managed hash = new SHA256Managed();
            byte[] bytes = hash.ComputeHash(Encoding.ASCII.GetBytes(value));
            foreach (byte b in bytes)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 获取字符串的Sha512哈希值
        /// </summary>
        public static string GetSHA512(string value)
        {
            

            StringBuilder sb = new StringBuilder();
            SHA512Managed hash = new SHA512Managed();
            byte[] bytes = hash.ComputeHash(Encoding.ASCII.GetBytes(value));
            foreach (byte b in bytes)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }
    }
}