using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace API
{
    public class JwtCustomClaims
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
    }

    public class JwtResponse
    {
        public string Token { get; set; }
        public long ExpiresAt { get; set; }
    }

    public interface IJwtHandler
    {
        JwtResponse CreateToken(JwtCustomClaims claims);
        bool ValidateToken(string token);
        string GenerateLink(string token);
    }

    public static class TypeConverterExtension
    {
        public static byte[] ToByteArray(this string value) =>
         Convert.FromBase64String(value);
    }

    public class JwtHandler: IJwtHandler
    {

        public JwtResponse CreateToken(JwtCustomClaims claims)
        {
            var privateKey = "base64PrivateKey".ToByteArray();

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

            var jwt = new JwtSecurityToken(
                claims: new Claim[] {
                    new Claim(nameof(claims.FirstName), claims.FirstName),
                    new Claim(nameof(claims.LastName), claims.LastName),
                    new Claim(nameof(claims.Email), claims.Email)
                },
                notBefore: now,
                expires: now.AddMinutes(30),
                signingCredentials: signingCredentials
            );

            string token = new JwtSecurityTokenHandler().WriteToken(jwt);

            return new JwtResponse
            {
                Token = token,
                ExpiresAt = unixTimeSeconds,
            };
        }

        public bool ValidateToken(string token)
        {

            var publicKey = "base64publicKey".ToByteArray();

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKey, out _);

            var validationParameters = new TokenValidationParameters
            {
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
            }
            catch
            {
                return false;
            }

            return true;
        }

    }
}
