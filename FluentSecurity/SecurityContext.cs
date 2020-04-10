using System;
using System.Collections.Generic;
using System.Configuration;
using System.Dynamic;
using FluentSecurity.ServiceLocation;

namespace FluentSecurity
{
	public class SecurityContext : ISecurityContext
	{
		private SecurityContext(ISecurityRuntime runtime)
		{
			Id = Guid.NewGuid();
			Data = new ExpandoObject();
			Runtime = runtime;

			var modifier = runtime.SecurityContextModifyer;
            modifier?.Invoke(this);
        }

		public Guid Id { get; }
		public dynamic Data { get; }
		public ISecurityRuntime Runtime { get; }

		public bool CurrentUserIsAuthenticated()
		{
			return Runtime.IsAuthenticated.Invoke();
		}

		public IEnumerable<object> CurrentUserRoles()
		{
			return Runtime.Roles?.Invoke();
		}

		public static ISecurityContext Current => ServiceLocator.Current.Resolve<ISecurityContext>();

        internal static ISecurityContext CreateFrom(ISecurityConfiguration configuration)
		{
			ISecurityContext context = null;

            if (configuration is SecurityConfiguration securityConfiguration)
			{
				var externalServiceLocator = securityConfiguration.Runtime.ExternalServiceLocator;
				if (externalServiceLocator != null)
					context = externalServiceLocator.Resolve(typeof(ISecurityContext)) as ISecurityContext;

				if (context == null)
				{
					if (securityConfiguration.Runtime.IsAuthenticated == null)
						throw new ConfigurationErrorsException(
							@"
							The current configuration is invalid! Before using Fluent Security you must do one of the following.
							1) Specify how to get the authentication status using GetAuthenticationStatusFrom().
							2) Register an instance of ISecurityContext in your IoC-container and register your container using ResolveServicesUsing().
							");

					context = new SecurityContext(securityConfiguration.Runtime);
				}
			}

			return context;
		}
	}
}