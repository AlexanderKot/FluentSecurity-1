using System;

namespace FluentSecurity.Caching
{
	public class PolicyResultCacheStrategy
	{
		public PolicyResultCacheStrategy(string controllerName, string actionName, Type policyType, Cache cacheLifecycle, By cacheLevel = By.ControllerAction)
		{
			ControllerName = controllerName;
			ActionName = actionName;
			PolicyType = policyType;
			CacheLifecycle = cacheLifecycle;
			CacheLevel = cacheLevel;
		}

		public string ControllerName { get; }
		public string ActionName { get; }
		public Type PolicyType { get; }
		public Cache CacheLifecycle { get; }
		public By CacheLevel { get; }
	}
}