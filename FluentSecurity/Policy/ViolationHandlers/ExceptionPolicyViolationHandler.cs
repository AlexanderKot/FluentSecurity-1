using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity.Policy.ViolationHandlers
{
	public class ExceptionPolicyViolationHandler : IPolicyViolationHandler
	{
		public ActionResult Handle(PolicyViolationException exception)
		{
			throw exception;
		}
	}
}