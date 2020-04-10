using System;
using System.Collections;

namespace FluentSecurity.ServiceLocation.LifeCycles
{
	internal class HttpContextLifecycle : ILifecycle
	{
		public const string CacheKey = "FluentSecurity-HttpContextCache";

		public static Func<bool> HasContextResolver;
		public static Func<IDictionary> DictionaryResolver;

		public HttpContextLifecycle()
		{
			HasContextResolver = () => SecurityRuntime.HttpContextAccessor.HttpContext != null;
			DictionaryResolver = () => SecurityRuntime.HttpContextAccessor.HttpContext.Items as IDictionary;
		}

		public IObjectCache FindCache()
		{
			var items = FindHttpDictionary();
			if (!items.Contains(CacheKey))
			{
				lock (items.SyncRoot)
				{
					if (!items.Contains(CacheKey))
					{
						var cache = new ObjectCache();
						items.Add(CacheKey, cache);
						return cache;
					}
				}
			}

			return (ObjectCache)items[CacheKey];
		}

		public static bool HasContext()
		{
			return HasContextResolver.Invoke();
		}

		private IDictionary FindHttpDictionary()
		{
			if (!HasContext()) throw new InvalidOperationException("HttpContext is not available.");
			return DictionaryResolver.Invoke();
		}
	}
}