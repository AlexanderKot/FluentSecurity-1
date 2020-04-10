using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity
{
	public interface IPolicyViolationHandler
	{
		ActionResult Handle(PolicyViolationException exception);
	}
}