﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using FluentSecurity.Internals;

namespace FluentSecurity.Scanning.TypeScanners
{
	internal class ControllerTypeScanner : ITypeScanner
	{
		public Type ControllerType { get; }
		
		public ControllerTypeScanner() : this(typeof(Controller)) {}

		public ControllerTypeScanner(Type controllerType)
		{
			if (controllerType == null) throw new ArgumentNullException(nameof(controllerType));
			
			ControllerType = controllerType;
		}

		public IEnumerable<Type> Scan(IEnumerable<Assembly> assemblies)
		{
			var results = new List<Type>();
			foreach (var assembly in assemblies)
			{
				var controllerTypes = ControllerType.IsGenericType
					? assembly.GetLoadableExportedTypes().Where(type => ControllerType.IsAssignableFromGenericType(type)).ToList()
					: assembly.GetLoadableExportedTypes().Where(type => ControllerType.IsAssignableFrom(type)).ToList();

				var filteredControllerTypes = controllerTypes.Where(type => !type.IsAbstract);
				results.AddRange(filteredControllerTypes);
			}
			return results;
		}
	}
}