using System;
using System.Collections.Specialized;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace FluentSecurity.Specification.Helpers
{
	public static class MvcMockHelpers
	{
		public static HttpContext FakeHttpContext()
		{
			var context = new Mock<HttpContext>();
			var request = new Mock<HttpRequest>();
			var response = new Mock<HttpResponse>();
			var session = new Mock<ISession>();
			var server = new Mock<HttpContext>();

			context.Setup(ctx => ctx.Request).Returns(request.Object);
			context.Setup(ctx => ctx.Response).Returns(response.Object);
			context.Setup(ctx => ctx.Session).Returns(session.Object);
			//context.Setup(ctx => ctx.Server).Returns(server.Object);

			return context.Object;
		}

		public static HttpContext FakeHttpContext(string url)
		{
			HttpContext context = FakeHttpContext();
			context.Request.SetupRequestUrl(url);
			return context;
		}

		static string GetUrlFileName(string url)
		{
			if (url.Contains("?"))
				return url.Substring(0, url.IndexOf("?"));
			return url;
		}

		static QueryString GetQueryStringParameters(string url)
		{
			if (url.Contains("?"))
			{
				var parameters = new QueryString();

				string[] parts = url.Split("?".ToCharArray());
				string[] keys = parts[1].Split("&".ToCharArray());

				foreach (string key in keys)
				{
					string[] part = key.Split("=".ToCharArray());
					parameters.Add(part[0], part[1]);
				}

				return parameters;
			}
			return QueryString.Empty;
		}

		private static void SetupRequestUrl(this HttpRequest request, string url)
		{
			if (url == null)
				throw new ArgumentNullException("url");

			if (!url.StartsWith("~/"))
				throw new ArgumentException("Sorry, we expect a virtual url starting with \"~/\".");

			var mock = Mock.Get(request);

			mock.Setup(req => req.QueryString)
				.Returns(GetQueryStringParameters(url));
			mock.Setup(req => req.PathBase) //AppRelativeCurrentExecutionFilePath)
				.Returns(GetUrlFileName(url));
			mock.Setup(req => req.Path)
				.Returns(string.Empty);
		}
	}

}