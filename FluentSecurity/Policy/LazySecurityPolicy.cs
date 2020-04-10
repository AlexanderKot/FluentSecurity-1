using System;
using FluentSecurity.Internals;

namespace FluentSecurity.Policy
{
	internal class LazySecurityPolicy<TSecurityPolicy> : ILazySecurityPolicy where TSecurityPolicy : ISecurityPolicy
	{
		public Type PolicyType => typeof (TSecurityPolicy);

        public ISecurityPolicy Load()
		{
			var externalServiceLocator = SecurityConfiguration.Current.Runtime.ExternalServiceLocator;
			if (externalServiceLocator != null)
			{
                if (externalServiceLocator.Resolve(PolicyType) is ISecurityPolicy securityPolicy) return securityPolicy;
			}

			return PolicyType.HasEmptyConstructor()
				? (ISecurityPolicy)Activator.CreateInstance<TSecurityPolicy>()
				: null;
		}

		public PolicyResult Enforce(ISecurityContext context)
		{
			var securityPolicy = Load();
			if (securityPolicy == null)
				throw new InvalidOperationException(
                    $"A policy of type {PolicyType.FullName} could not be loaded! Make sure the policy has an empty constructor or is registered in your IoC-container."
                );
			
			return securityPolicy.Enforce(context);
		}
	}
}