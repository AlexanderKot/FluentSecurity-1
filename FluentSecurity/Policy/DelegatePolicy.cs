using System;
using Microsoft.AspNetCore.Mvc;
using FluentSecurity.Policy.Contexts;
using FluentSecurity.Policy.Results;

namespace FluentSecurity.Policy
{
	public class DelegatePolicy : ISecurityPolicy
	{
		public string Name { get; }
		public Func<DelegateSecurityContext, PolicyResult> Policy { get; }
		public Func<PolicyViolationException, ActionResult> ViolationHandler { get; }

		public DelegatePolicy(string uniqueName, Func<DelegateSecurityContext, PolicyResult> policyDelegate, Func<PolicyViolationException, ActionResult> violationHandlerDelegate = null)
		{
			if (string.IsNullOrWhiteSpace(uniqueName))
				throw new ArgumentException(nameof(uniqueName));

            Name = uniqueName;
			Policy = policyDelegate ?? throw new ArgumentNullException(nameof(policyDelegate));
			ViolationHandler = violationHandlerDelegate;
		}

		public PolicyResult Enforce(ISecurityContext context)
		{
			var wrappedContext = new DelegateSecurityContext(this, context);
			var policyResult = Policy.Invoke(wrappedContext);
			return new DelegatePolicyResult(policyResult, Name, ViolationHandler);
		}
	}
}