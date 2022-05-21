using System.Collections.Generic;
using System.Reflection;

namespace FluentSecurity
{
	public interface ISecurityConfiguration
	{
		ISecurityRuntime Runtime { get; }
		IReadOnlyDictionary<(string controllerName, string actionName), IPolicyContainer> PolicyContainers { get; }
		void AssertAllActionsAreConfigured();
		void AssertAllActionsAreConfigured(Assembly[] assemblies);
		string WhatDoIHave();
	}
}