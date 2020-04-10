using System.Collections.Generic;
using System.Security.Claims;

namespace FluentSecurity.SampleApplication.Models
{
	public class User : IUser
	{
		public User()
		{
			Roles = new List<UserRole>();
		}

		public IEnumerable<UserRole> Roles { get; set; }

        public static implicit operator ClaimsPrincipal(User v)
        {
            return null;
        }
	}
}