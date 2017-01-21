using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreAuthenticationManager
{
	public class TokenManager
	{
		static TokenManager tokenManagerInstance;
		SigningCredentials signingCredentials;
		TokenValidationParameters tokenValidationParapeters;
		JwtSecurityTokenHandler handler;

		internal TokenManager(string securityKey, string issuerName, string audienceName)
		{
			var securityKeyBytes = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.Default.GetBytes(securityKey));
			signingCredentials = new SigningCredentials(securityKeyBytes, SecurityAlgorithms.HmacSha256Signature);
			tokenValidationParapeters = new TokenValidationParameters
			{
				IssuerSigningKey = signingCredentials.Key,
				ValidateLifetime = true,
				ValidAudience = audienceName,
				ValidIssuer = audienceName
			};

			handler = new JwtSecurityTokenHandler();
		}

		internal ClaimsPrincipal ValidateToken(string token)
		{
			var jwtToken = handler.ReadToken(token);
			var claims = handler.ValidateToken(token, tokenValidationParapeters, out jwtToken);

			return claims;
		}

		internal static TokenManager GetInstance(string securityKey, string issuerName, string audienceName)
		{
			if (tokenManagerInstance == null)
			{
				tokenManagerInstance = new TokenManager(securityKey, issuerName, audienceName);
			}

			return tokenManagerInstance;
		}

		public static TokenManager GetInstance()
		{
			return tokenManagerInstance;
		}

		public string GetTokenString(ClaimsIdentity claims, TimeSpan tokenValidTime)
		{
			var tokenDescriptor = new SecurityTokenDescriptor();
			tokenDescriptor.Issuer = tokenValidationParapeters.ValidIssuer;
			tokenDescriptor.Audience = tokenValidationParapeters.ValidAudience;
			tokenDescriptor.SigningCredentials = signingCredentials;
			tokenDescriptor.Subject = claims;
			tokenDescriptor.Expires = DateTime.Now.Add(tokenValidTime);

			var cookieToken = handler.CreateToken(tokenDescriptor);

			return handler.WriteToken(cookieToken);
		}

		public void AppendTokenCookieToResponse(ClaimsIdentity claims, TimeSpan tokenValidTime, HttpResponse response)
		{
			var token = GetTokenString(claims, tokenValidTime);

			response.Cookies.Append(Consts.AUTHENTICATION_COOKIE_NAME, token, new CookieOptions { Expires = DateTime.Now.Add(tokenValidTime) });
		}
	}
}
