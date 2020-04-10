using System;
using System.Linq;
using FluentSecurity.Caching;
using FluentSecurity.Policy.ViolationHandlers.Conventions;

namespace FluentSecurity.Configuration
{
	public class AdvancedConfiguration
	{
		private readonly SecurityRuntime _runtime;

		internal AdvancedConfiguration(SecurityRuntime runtime)
		{
            _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));

			if (!_runtime.Conventions.Any())
			{
				Conventions(conventions =>
				{
					conventions.Add(new FindByPolicyNameConvention());
					conventions.Add(new FindDefaultPolicyViolationHandlerByNameConvention());
				});
			}
		}

		public void IgnoreMissingConfiguration()
		{
			_runtime.ShouldIgnoreMissingConfiguration = true;
		}

		public void ModifySecurityContext(Action<ISecurityContext> modifier)
		{
			_runtime.SecurityContextModifyer = modifier;
		}

		public void SetDefaultResultsCacheLifecycle(Cache lifecycle)
		{
			_runtime.DefaultResultsCacheLifecycle = lifecycle;
		}

		public void Violations(Action<ViolationConfiguration> violationConfiguration)
		{
			if (violationConfiguration == null) throw new ArgumentNullException(nameof(violationConfiguration));
			_runtime.ApplyConfiguration(violationConfiguration);
		}

		public void Conventions(Action<ConventionConfiguration> conventions)
		{
			if (conventions == null) throw new ArgumentNullException(nameof(conventions));
			_runtime.ApplyConfiguration(conventions);
		}
	}
}