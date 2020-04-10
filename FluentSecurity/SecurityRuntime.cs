using System;
using System.Collections.Generic;
using System.Linq;
using FluentSecurity.Caching;
using FluentSecurity.Configuration;
using Microsoft.AspNetCore.Http;

namespace FluentSecurity
{
	internal class SecurityRuntime : ISecurityRuntime
	{
		private readonly List<ProfileImport> _profiles = new List<ProfileImport>();
		private readonly List<IPolicyContainer> _policyContainers = new List<IPolicyContainer>();
		private readonly List<IConvention> _conventions = new List<IConvention>();
		public static IHttpContextAccessor HttpContextAccessor;

		public Func<bool> IsAuthenticated { get; internal set; }
		public Func<IEnumerable<object>> Roles { get; internal set; }
		public ISecurityServiceLocator ExternalServiceLocator { get; internal set; }

		public IEnumerable<Type> Profiles { get { return _profiles.Where(pi => pi.Completed).Select(pi => pi.Type); } }
		public IEnumerable<IPolicyContainer> PolicyContainers => _policyContainers.AsReadOnly();
        public IEnumerable<IConvention> Conventions => _conventions.AsReadOnly();

        public Cache DefaultResultsCacheLifecycle { get; internal set; }
		public Action<ISecurityContext> SecurityContextModifyer { get; internal set; }
		public bool ShouldIgnoreMissingConfiguration { get; internal set; }

		public SecurityRuntime()
		{
			ShouldIgnoreMissingConfiguration = false;
			DefaultResultsCacheLifecycle = Cache.DoNotCache;
		}

		public void ApplyConfiguration(Action<ConventionConfiguration> conventionConfiguration)
		{
			if (conventionConfiguration == null) throw new ArgumentNullException(nameof(conventionConfiguration));
			var configuration = new ConventionConfiguration(_conventions);
			conventionConfiguration.Invoke(configuration);
		}

		public void ApplyConfiguration(Action<ViolationConfiguration> violationConfiguration)
		{
			if (violationConfiguration == null) throw new ArgumentNullException(nameof(violationConfiguration));
			var conventionsConfiguration = new ConventionConfiguration(_conventions);
			var configuration = new ViolationConfiguration(conventionsConfiguration);
			violationConfiguration.Invoke(configuration);
		}

		public void ApplyConfiguration(SecurityProfile profileConfiguration)
		{
			if (profileConfiguration == null) throw new ArgumentNullException(nameof(profileConfiguration));
			
			var profileType = profileConfiguration.GetType();
			if (_profiles.Any(pi => pi.Type == profileType)) return;

			var profileImport = new ProfileImport(profileType);
			_profiles.Add(profileImport);

			profileConfiguration.Initialize(this);
			profileConfiguration.Configure();
			
			profileImport.MarkCompleted();
		}

		public PolicyContainer AddPolicyContainer(PolicyContainer policyContainer)
		{
			if (policyContainer == null) throw new ArgumentNullException(nameof(policyContainer));

			var existingContainer = PolicyContainers.GetContainerFor(policyContainer.ControllerName, policyContainer.ActionName);
			if (existingContainer != null) return (PolicyContainer) existingContainer;

			_policyContainers.Add(policyContainer);

			return policyContainer;
		}
	}
}