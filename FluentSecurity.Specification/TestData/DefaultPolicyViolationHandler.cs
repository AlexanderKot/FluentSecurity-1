using System;
using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity.Specification.TestData
{
	public class DefaultPolicyViolationHandler : IPolicyViolationHandler
	{
		public ActionResult Handle(PolicyViolationException exception)
		{
			throw new NotImplementedException();
		}
	}
}