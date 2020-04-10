using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using FluentSecurity.SampleApplication.Models;
using FluentSecurity.SampleApplication.Helpers;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;


namespace FluentSecurity.SampleApplication.Controllers
{
    public class AccountController : Controller
    {
        public async Task<ActionResult> LogInAsAdministrator()
        {
            await Authenticate("Administrator", UserRole.Administrator);
			return Redirect("../Home");
		}

		public async Task<ActionResult> LogInAsPublisher()
		{
			await Authenticate("Publisher", UserRole.Publisher);
			return Redirect("../Home");
		}

		public async Task<ActionResult> LogOut()
		{
			await System.Web.HttpContext.Current.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
			return Redirect("../Home");
		}

		public IUser GetCurrentUser()
        {
			var claim = System.Web.HttpContext.Current?.User.FindFirst(x => x.Type == ClaimsIdentity.DefaultRoleClaimType)?.Value;
			Enum.TryParse(typeof(UserRole), claim, true, out var role);
			if (claim == null) return null;
			User User = new User
			{
                Roles = new List<UserRole>
				{
					(UserRole)role
				}
			};
			return User;
		}

        private async Task Authenticate(string userName, UserRole role)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, userName),
				new Claim(ClaimsIdentity.DefaultRoleClaimType, role.ToString())
            };

            ClaimsIdentity id = new ClaimsIdentity(claims, "ApplicationCookie", ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            
            await System.Web.HttpContext.Current.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id));
        }
	}
}