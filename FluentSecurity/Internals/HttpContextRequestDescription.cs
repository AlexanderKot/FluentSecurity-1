using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using System;

namespace FluentSecurity.Internals
{
	public class HttpContextRequestDescription : IRequestDescription
	{
		internal static readonly Func<HttpContext> DefaultHttpContextProvider = () => SecurityRuntime.HttpContextAccessor.HttpContext; //new HttpContextWrapper(HttpContext.Current);
		internal static Func<HttpContext> HttpContextProvider = DefaultHttpContextProvider;

		public HttpContextRequestDescription()
		{
			var route = GetRoute();
			AreaName = route.GetAreaName();
			ControllerName = (string)route.Values["controller"];
			ActionName = (string)route.Values["action"];
		}

		private static RouteData GetRoute()
		{
			var httpContext = HttpContextProvider();
			var routeData = httpContext.GetRouteData();//RouteTable.Routes.GetRouteData(httpContext);
			return routeData ?? new RouteData();
		}

		public string AreaName { get; }
		public string ControllerName { get; }
		public string ActionName { get; }
	}
}