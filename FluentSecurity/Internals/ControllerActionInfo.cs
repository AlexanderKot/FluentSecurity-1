using System;
using System.Reflection;

namespace FluentSecurity.Internals
{
	public class ControllerActionInfo
	{
		public Type ControllerType { get; }
		public string ActionName { get; }
		public Type ActionResultType { get; }

		internal ControllerActionInfo(Type controller, MethodInfo action)
		{
			ControllerType = controller;
			ActionName = action.GetActionName();
			ActionResultType = action.ReturnType;
		}
	}
}