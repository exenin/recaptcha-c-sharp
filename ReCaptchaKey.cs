using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Text;
using System.Web.Script.Serialization;

/// <summary>
/// Summary description for ReCaptchaKey
/// </summary>
public class ReCaptchaKey {
    public ReCaptchaKey() {
        _siteKey = "You_Site_Public_Key";
        _SecretKey = "You_Site_Secret_KEY";
        _encryptedTokenString = EncryptedToken();
    }

    private string _siteKey;
    private string _SecretKey;
    private string _encryptedTokenString;

    public string SiteKey {
        get { return _siteKey; }
    }
    public string Token {
        get { return _encryptedTokenString; }
    }

    private class SessionTokenObject {
        public string session_id { get; set; }
        public string ts_ms { get; set; }
    }

    public string EncryptedToken() {
        return Encrypt(CreateJsonToken(), _SecretKey);
    }


    public long current_TimeMillis(DateTime d) {
        DateTime Jan1st1970 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return (long)((DateTime.UtcNow - Jan1st1970).TotalMilliseconds);
    }

    private string CreateJsonToken() {
        SessionTokenObject sto = new SessionTokenObject();
        sto.session_id = Guid.NewGuid().ToString();
        sto.ts_ms = current_TimeMillis(DateTime.UtcNow).ToString();
        var json = new JavaScriptSerializer().Serialize(sto);
        return json;
    }
    
    // Encryption examples tributed to > https://zenu.wordpress.com/2011/09/21/aes-128bit-cross-platform-java-and-c-encryption-compatibility/
    public RijndaelManaged GetRijndaelManaged(String secretKey) {
        var keyBytes = new byte[16];
        var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
        SHA1 sha1 = new SHA1CryptoServiceProvider();

        Array.Copy(sha1.ComputeHash(secretKeyBytes), keyBytes, 16);
        return new RijndaelManaged {
            Mode = CipherMode.ECB,
            Padding = PaddingMode.PKCS7,
            KeySize = 128,
            BlockSize = 128,
            Key = keyBytes,
            IV = keyBytes
        };
    }

    public byte[] Encrypt(byte[] plainBytes, RijndaelManaged rijndaelManaged) {
        return rijndaelManaged.CreateEncryptor()
            .TransformFinalBlock(plainBytes, 0, plainBytes.Length);
    }

    public byte[] Decrypt(byte[] encryptedData, RijndaelManaged rijndaelManaged) {
        return rijndaelManaged.CreateDecryptor()
            .TransformFinalBlock(encryptedData, 0, encryptedData.Length);
    }

    public String Encrypt(String plainText, String key) {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] returned = Encrypt(plainBytes, GetRijndaelManaged(key));


        string stSendTHis = HttpServerUtility.UrlTokenEncode(returned);

        return stSendTHis.Remove(stSendTHis.Length - 1);
    }



}