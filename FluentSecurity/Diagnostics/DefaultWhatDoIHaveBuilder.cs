using System.Linq;
using System.Text;

namespace FluentSecurity.Diagnostics
{
	public class DefaultWhatDoIHaveBuilder : IWhatDoIHaveBuilder
	{
		public string WhatDoIHave(ISecurityConfiguration configuration)
		{
			var builder = new StringBuilder();

			builder.AppendFormat("Ignore missing configuration: {0}", configuration.Runtime.ShouldIgnoreMissingConfiguration);

			builder.AppendLine().AppendLine().AppendLine("------------------------------------------------------------------------------------").AppendLine();

			foreach (var policyContainer in configuration.PolicyContainers.OrderBy(x => x.Value.ControllerName).ThenBy(x => x.Value.ActionName))
			{
				builder.AppendFormat(
					"{0} > {1}{2}",
					policyContainer.Value.ControllerName,
					policyContainer.Value.ActionName,
					policyContainer.Value.GetPolicies().ToText()
					);
				builder.AppendLine().AppendLine();
			}

			builder.Append("------------------------------------------------------------------------------------");

			return builder.ToString();
		}
	}
}