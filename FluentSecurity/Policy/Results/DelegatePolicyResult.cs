using System;
using Microsoft.AspNetCore.Mvc;

namespace FluentSecurity.Policy.Results
{
	public class DelegatePolicyResult : PolicyResult
	{
		public string PolicyName { get; }
		public Func<PolicyViolationException, ActionResult> ViolationHandler { get; }

		public DelegatePolicyResult(PolicyResult policyResult, string policyName, Func<PolicyViolationException, ActionResult> violationHandler)
			: base(policyResult.Message, policyResult.ViolationOccured, policyResult.PolicyType)
		{
			if (string.IsNullOrWhiteSpace(policyName))
				throw new ArgumentException("policyName");

			PolicyName = policyName;
			ViolationHandler = violationHandler;
		}
	}
}