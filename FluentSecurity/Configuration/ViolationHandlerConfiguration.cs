using System;
using FluentSecurity.Policy;
using FluentSecurity.Policy.ViolationHandlers.Conventions;

namespace FluentSecurity.Configuration
{
	public class ViolationHandlerConfiguration<TSecurityPolicy> : ViolationHandlerConfigurationBase where TSecurityPolicy : class, ISecurityPolicy
	{
		internal ViolationHandlerConfiguration(ViolationConfiguration violationConfiguration) : base(violationConfiguration) {}

		public void IsHandledBy<TPolicyViolationHandler>() where TPolicyViolationHandler : class, IPolicyViolationHandler
		{
			ViolationConfiguration.AddConvention(new PolicyTypeToPolicyViolationHandlerTypeConvention<TSecurityPolicy, TPolicyViolationHandler>());
		}

		public void IsHandledBy<TPolicyViolationHandler>(Func<TPolicyViolationHandler> policyViolationHandlerFactory) where TPolicyViolationHandler : class, IPolicyViolationHandler
		{
			ViolationConfiguration.AddConvention(new PolicyTypeToPolicyViolationHandlerInstanceConvention<TSecurityPolicy, TPolicyViolationHandler>(policyViolationHandlerFactory));
		}
	}

	public class ViolationHandlerConfiguration : ViolationHandlerConfigurationBase
	{
		public Func<PolicyResult, bool> Predicate { get; }

		internal ViolationHandlerConfiguration(ViolationConfiguration violationConfiguration, Func<PolicyResult, bool> predicate) : base(violationConfiguration)
		{
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
		}

		public void IsHandledBy<TPolicyViolationHandler>() where TPolicyViolationHandler : class, IPolicyViolationHandler
		{
			ViolationConfiguration.AddConvention(new PredicateToPolicyViolationHandlerTypeConvention<TPolicyViolationHandler>(Predicate));
		}

		public void IsHandledBy<TPolicyViolationHandler>(Func<TPolicyViolationHandler> policyViolationHandlerFactory) where TPolicyViolationHandler : class, IPolicyViolationHandler
		{
			ViolationConfiguration.AddConvention(new PredicateToPolicyViolationHandlerInstanceConvention<TPolicyViolationHandler>(policyViolationHandlerFactory, Predicate));
		}
	}

	public abstract class ViolationHandlerConfigurationBase
	{
		protected ViolationConfiguration ViolationConfiguration { get; }

		internal ViolationHandlerConfigurationBase(ViolationConfiguration violationConfiguration)
		{
            ViolationConfiguration = violationConfiguration ?? throw new ArgumentNullException(nameof(violationConfiguration));
		}
	}
}