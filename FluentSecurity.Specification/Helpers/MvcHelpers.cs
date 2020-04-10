using System;
using System.Linq.Expressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Moq;

namespace FluentSecurity.Specification.Helpers
{
	public static class MvcHelpers
	{
		public static AuthorizationFilterContext GetAuthorizationContextFor<TController>(Expression<Func<TController, object>> actionExpression) where TController : Controller
		{
			var controllerName = typeof(TController).GetControllerName();
			var actionName = actionExpression.GetActionName();

			var filterContext = new Mock<AuthorizationFilterContext>();

			var controllerDescriptor = new Mock<ControllerActionDescriptor>();
			controllerDescriptor.Setup(x => x.ControllerName).Returns(controllerName);
			controllerDescriptor.Setup(x => x.ControllerTypeInfo.AsType()).Returns(typeof(TController));
			//controllerDescriptor.Replay();

			var actionDescriptor = new Mock<ActionDescriptor>();
			actionDescriptor.Setup(x => x.DisplayName).Returns(actionName);
			actionDescriptor.Setup(x  => x.FilterDescriptors as ControllerActionDescriptor).Returns(controllerDescriptor.Object);
			//actionDescriptor.Replay();

			filterContext.Setup(x => x.ActionDescriptor).Returns(actionDescriptor.Object);
			//filterContext.Replay();

			var routeData = new RouteData();
			filterContext.Setup(x => x.RouteData).Returns(routeData);
			//filterContext.Replay();

			return filterContext.Object;
		}

		private static string GetControllerName(this Type controllerType)
		{
			return controllerType.Name.Replace("Controller", string.Empty);
		}

		private static string GetActionName(this LambdaExpression actionExpression)
		{
			return ((MethodCallExpression)actionExpression.Body).Method.GetActionName();
		}
	}
}