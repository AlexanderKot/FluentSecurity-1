using FluentSecurity.Caching;
using FluentSecurity.Diagnostics;
using FluentSecurity.Internals;
using FluentSecurity.ServiceLocation;
using Microsoft.AspNetCore.Http;
using NUnit.Framework;
using Moq;

namespace FluentSecurity.Specification // Do not change the namespace
{
	[SetUpFixture]
	public class ResetFixture
	{
		[OneTimeSetUp]//[SetUp] 
		public void Reset()
		{
			ServiceLocator.Reset();
			ExceptionFactory.Reset();
			SecurityDoctor.Reset();
			SecurityRuntime.HttpContextAccessor = new Mock<IHttpContextAccessor>().Object;
			SecurityCache.ClearCache(Lifecycle.HybridHttpContext);			
			SecurityCache.ClearCache(Lifecycle.HybridHttpSession);
		}
	}
}