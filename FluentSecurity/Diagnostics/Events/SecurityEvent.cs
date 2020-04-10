using System;

namespace FluentSecurity.Diagnostics.Events
{
	public abstract class SecurityEvent : ISecurityEvent
	{
		protected SecurityEvent(Guid correlationId, string message)
		{
			CorrelationId = correlationId;
			Message = message;
		}

		public Guid CorrelationId { get; }
		public string Message { get; }
		public long? CompletedInMilliseconds { get; set; }
	}
}