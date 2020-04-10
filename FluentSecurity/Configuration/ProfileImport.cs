using System;

namespace FluentSecurity.Configuration
{
	internal class ProfileImport
	{
		public ProfileImport(Type type)
		{
			Type = type;
		}

		public Type Type { get; }
		public bool Completed { get; private set; }

		public void MarkCompleted()
		{
			Completed = true;
		}
	}
}