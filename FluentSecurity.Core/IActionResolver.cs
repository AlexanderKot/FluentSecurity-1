﻿using System;
using System.Collections.Generic;
using System.Reflection;
using FluentSecurity.Internals;

namespace FluentSecurity.Core
{
	public interface IActionResolver
	{
		IEnumerable<MethodInfo> Resolve(Type controllerType, Func<ControllerActionInfo, bool> actionFilter = null);
	}
}