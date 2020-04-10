using System;
using FluentSecurity.Policy;
using FluentSecurity.Policy.ViolationHandlers.Conventions;

namespace FluentSecurity.Configuration
{
	public class ViolationConfiguration
	{
		private readonly ConventionConfiguration _conventionConfiguration;

		internal ViolationConfiguration(ConventionConfiguration conventionConfiguration)
		{
            _conventionConfiguration = conventionConfiguration ?? throw new ArgumentNullException(nameof(conventionConfiguration));
		}

		public void AddConvention(IPolicyViolationHandlerConvention convention)
		{
			if (convention == null) throw new ArgumentNullException(nameof(convention));
			_conventionConfiguration.Insert(0, convention);
		}

		public void RemoveConventions<TPolicyViolationHandlerConvention>() where TPolicyViolationHandlerConvention : class, IPolicyViolationHandlerConvention
		{
			RemoveConventions(c => c is TPolicyViolationHandlerConvention);
		}

		public void RemoveConventions(Func<IPolicyViolationHandlerConvention, bool> predicate)
		{
			if (predicate == null) throw new ArgumentNullException(nameof(predicate));
			
			_conventionConfiguration.RemoveAll(convention =>
				convention is IPolicyViolationHandlerConvention &&
				predicate.Invoke(convention as IPolicyViolationHandlerConvention)
				);
		}

		public ViolationHandlerConfiguration<TSecurityPolicy> Of<TSecurityPolicy>() where TSecurityPolicy : class, ISecurityPolicy
		{
			return new ViolationHandlerConfiguration<TSecurityPolicy>(this);
		}

		public ViolationHandlerConfiguration Of(Func<PolicyResult, bool> predicate)
		{
			return new ViolationHandlerConfiguration(this, predicate);
		}
	}
}