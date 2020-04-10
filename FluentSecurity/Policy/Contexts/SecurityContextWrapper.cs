using System;
using System.Collections.Generic;

namespace FluentSecurity.Policy.Contexts
{
	public class SecurityContextWrapper : ISecurityContext
	{
		private readonly ISecurityContext _securityContext;

		public SecurityContextWrapper(ISecurityContext securityContext)
		{
            _securityContext = securityContext ?? throw new ArgumentNullException(nameof(securityContext));
		}

		public Guid Id => _securityContext.Id;

        public dynamic Data => _securityContext.Data;

        public bool CurrentUserIsAuthenticated()
		{
			return _securityContext.CurrentUserIsAuthenticated();
		}

		public IEnumerable<object> CurrentUserRoles()
		{
			return _securityContext.CurrentUserRoles();
		}

		public ISecurityRuntime Runtime => _securityContext.Runtime;
    }
}