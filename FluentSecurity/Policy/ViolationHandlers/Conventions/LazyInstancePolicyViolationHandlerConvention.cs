using System;

namespace FluentSecurity.Policy.ViolationHandlers.Conventions
{
	public abstract class LazyInstancePolicyViolationHandlerConvention<TPolicyViolationHandler> : IPolicyViolationHandlerConvention where TPolicyViolationHandler : class, IPolicyViolationHandler
	{
		private readonly Func<TPolicyViolationHandler> _policyViolationHandlerFactory;

		public Func<PolicyResult, bool> Predicate { get; }

		protected LazyInstancePolicyViolationHandlerConvention(Func<TPolicyViolationHandler> policyViolationHandlerFactory) : this(policyViolationHandlerFactory, pr => true) {}

		protected LazyInstancePolicyViolationHandlerConvention(Func<TPolicyViolationHandler> policyViolationHandlerFactory, Func<PolicyResult, bool> predicate)
		{
            _policyViolationHandlerFactory = policyViolationHandlerFactory ?? throw new ArgumentNullException(nameof(policyViolationHandlerFactory));
			Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
		}

		public IPolicyViolationHandler GetHandlerFor(PolicyViolationException exception)
		{
			return Predicate.Invoke(exception.PolicyResult) ? _policyViolationHandlerFactory.Invoke() : null;
		}
	}
}