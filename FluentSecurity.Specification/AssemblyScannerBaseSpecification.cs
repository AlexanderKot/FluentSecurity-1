using System;
using System.Collections.Generic;
using FluentSecurity.Specification.Helpers;

namespace FluentSecurity.Specification
{
	public abstract class AssemblyScannerBaseSpecification
	{
		protected static void Because(Action<ConfigurationExpression> configurationExpression)
		{
			// Arrange
			PolicyContainers = new Dictionary<(string controllerName, string actionName), IPolicyContainer>();
			var expression = TestDataFactory.CreateValidConfigurationExpression();
			configurationExpression(expression);
			PolicyContainers = expression.Runtime.PolicyContainers;
		}

		protected static IReadOnlyDictionary<(string controllerName, string actionName), IPolicyContainer> PolicyContainers { get; private set; }
	}
}