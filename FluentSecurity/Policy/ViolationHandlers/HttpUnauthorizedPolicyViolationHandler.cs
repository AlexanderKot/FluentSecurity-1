using System;
using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity.Specification.Policy.ViolationHandlers
{
	public class HttpUnauthorizedPolicyViolationHandler : IPolicyViolationHandler
	{
		public ActionResult Handle(PolicyViolationException exception)
		{
			if (exception == null) throw new ArgumentNullException("exception");
			
			return new UnauthorizedResult(); //return new HttpUnauthorizedResult(exception.Message);
		}
	}
}