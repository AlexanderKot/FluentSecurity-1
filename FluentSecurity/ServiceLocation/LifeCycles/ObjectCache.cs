using System;
using System.Collections.Concurrent;

namespace FluentSecurity.ServiceLocation.LifeCycles
{
	[Serializable]
	internal class ObjectCache : IObjectCache
	{
		private readonly ConcurrentDictionary<object, object> _objects = new ConcurrentDictionary<object, object>();

		public int Count => _objects.Count;

        public object Get(object key)
		{
			var hasInstance = Has(key);
			return hasInstance ? _objects[key] : null;
		}

		public void Set(object key, object instance)
		{
			if (instance == null) return;
	
			if (Has(key))
			{
				var message = $"An instance for key {key} is already in the cache.";
				throw new ArgumentException(message, nameof(key));
			}

			_objects[key] = instance;
		}

		public void Clear()
		{
			_objects.Each(@object => TryDispose(@object.Value));
			_objects.Clear();
		}

		private static void TryDispose(object cachedObject)
		{
            if (cachedObject is IDisposable disposable) disposable.Dispose();
		}

		private bool Has(object key)
		{
			var containsKey = _objects.ContainsKey(key);
			return containsKey;
		}
	}
}