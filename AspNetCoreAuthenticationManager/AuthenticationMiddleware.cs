using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AspNetCoreAuthenticationManager
{
	public static class AuthenticationMiddleware
	{
		public static IApplicationBuilder UseAuthentication(this IApplicationBuilder app, string securityKey, string issuerName, string audienceName)
		{
			return app.Use(next => async ctx =>
			{
				var tokenManager = TokenManager.GetInstance(securityKey, issuerName, audienceName);
				try
				{
					var authCookie = ctx.Request.Cookies.FirstOrDefault(c => c.Key == Consts.AUTHENTICATION_COOKIE_NAME);
					if (!String.IsNullOrEmpty(authCookie.Value))
					{
						var claims = tokenManager.ValidateToken(authCookie.Value);

						ctx.User = claims;
					}
					await next(ctx);
				}
				catch (Exception exc)
				{
					if (ctx.Response.HasStarted)
					{
						throw exc;
					}

					ctx.Response.Cookies.Append(Consts.AUTHENTICATION_COOKIE_NAME, "deleted", new CookieOptions { Expires = DateTime.Now.AddDays(-1) });
					ctx.User = new ClaimsPrincipal();
				}
			});
		}
	}
}
