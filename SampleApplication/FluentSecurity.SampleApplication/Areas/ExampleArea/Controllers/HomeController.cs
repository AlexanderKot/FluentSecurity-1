using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity.SampleApplication.Areas.ExampleArea.Controllers
{
	[Area("ExampleArea")]
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
			return View();
		}

		public ActionResult PublishersOnly()
		{
			return View();
		}

		public ActionResult AdministratorsOnly()
		{
			return View();
		}
	}
}