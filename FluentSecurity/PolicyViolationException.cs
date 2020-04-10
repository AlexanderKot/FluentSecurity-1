using System;

namespace FluentSecurity
{
	public class PolicyViolationException : Exception
	{
		public PolicyViolationException(PolicyResult policyResult, ISecurityContext securityContext) : base(policyResult.Message)
		{
			PolicyResult = policyResult;
			SecurityContext = securityContext;
			PolicyType = PolicyResult.PolicyType;
		}

		public PolicyResult PolicyResult { get; }
		public Type PolicyType { get; }
		public ISecurityContext SecurityContext { get; }
	}
}