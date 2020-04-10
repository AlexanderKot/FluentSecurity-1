using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity.TestHelper.Specification.TestData
{
	public class TaskController : Controller
	{
		public Task<ActionResult> LongRunningAction()
		{
			return null;
		}

		public Task<JsonResult> LongRunningJsonAction()
		{
			return null;
		}
	}
}
