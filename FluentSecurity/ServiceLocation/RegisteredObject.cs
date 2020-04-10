using System;

namespace FluentSecurity.ServiceLocation
{
	internal class RegisteredObject
	{
		public RegisteredObject(Type typeToResolve, Func<IContainer, object> instanceExpression, Lifecycle lifecycle)
		{
			TypeToResolve = typeToResolve;
			InstanceExpression = instanceExpression;
			InstanceKey = Guid.NewGuid();
			Lifecycle = lifecycle;
		}

		public Type TypeToResolve { get; }
		public Guid InstanceKey { get; }
		public Func<IContainer, object> InstanceExpression { get; }
		public Lifecycle Lifecycle { get; }

		public object CreateInstance(IContainer container)
		{
			return InstanceExpression.Invoke(container);
		}
	}
}