using System;
using FluentSecurity.ServiceLocation;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.DependencyInjection;

namespace FluentSecurity
{
	[AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
	public class HandleSecurityAttribute : Attribute, IAuthorizationFilter
	{
		internal ISecurityHandler Handler { get; }

		[ActivatorUtilitiesConstructor]
		public HandleSecurityAttribute() : this(ServiceLocator.Current.Resolve<ISecurityHandler>()) {}

		public HandleSecurityAttribute(ISecurityHandler securityHandler)
		{
			Handler = securityHandler;
		}

		public void OnAuthorization(AuthorizationFilterContext filterContext)
		{
			var descriptor = (ControllerActionDescriptor)filterContext.ActionDescriptor;
			var actionName = descriptor.ActionName;
			
			var controllerName = descriptor.ControllerTypeInfo.FullName;
			
			var securityContext = SecurityContext.Current;
			securityContext.Data.RouteValues = filterContext.RouteData.Values;

			var overrideResult = Handler.HandleSecurityFor(controllerName, actionName, securityContext);
			if (overrideResult != null) filterContext.Result = overrideResult;
		}
	}
}