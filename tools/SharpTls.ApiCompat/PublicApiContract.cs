using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace SharpTls.ApiCompatibility;

internal static class PublicApiContract
{
    private static readonly NullabilityInfoContext Nullability = new();

    internal static string Generate(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        var output = new StringBuilder();
        foreach (var type in assembly.GetExportedTypes().OrderBy(TypeSortName, StringComparer.Ordinal))
        {
            output.AppendLine(FormatTypeDeclaration(type));
            foreach (var member in GetMembers(type))
            {
                output.Append("  ").AppendLine(member);
            }
        }
        return output.ToString().ReplaceLineEndings("\n");
    }

    private static IEnumerable<string> GetMembers(Type type)
    {
        if (typeof(MulticastDelegate).IsAssignableFrom(type.BaseType))
        {
            return [];
        }

        const BindingFlags declared = BindingFlags.Public | BindingFlags.NonPublic |
                                      BindingFlags.Instance | BindingFlags.Static |
                                      BindingFlags.DeclaredOnly;
        var members = new List<string>();

        foreach (var constructor in type.GetConstructors(declared).Where(IsVisible))
        {
            members.Add($"C: {Visibility(constructor)} {TypeSortName(type)}({FormatParameters(constructor)})");
        }
        foreach (var field in type.GetFields(declared).Where(field =>
                     IsVisible(field) && !field.IsSpecialName &&
                     !field.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)))
        {
            var nullability = SafeNullability(field);
            var modifiers = field.IsLiteral
                ? "const "
                : field.IsStatic
                    ? field.IsInitOnly ? "static readonly " : "static "
                    : field.IsInitOnly ? "readonly " : string.Empty;
            var value = field.IsLiteral ? $" = {FormatConstant(field.GetRawConstantValue(), field.FieldType)}" : string.Empty;
            members.Add($"F: {Visibility(field)} {modifiers}{FormatType(field.FieldType, nullability)} {field.Name}{value}");
        }
        foreach (var property in type.GetProperties(declared).Where(IsVisible))
        {
            var getter = property.GetGetMethod(nonPublic: true);
            var setter = property.GetSetMethod(nonPublic: true);
            var accessor = getter is not null && IsVisible(getter) ? "get; " : string.Empty;
            accessor += setter is not null && IsVisible(setter)
                ? setter.ReturnParameter.GetRequiredCustomModifiers().Contains(typeof(IsExternalInit))
                    ? "init; "
                    : "set; "
                : string.Empty;
            var index = property.GetIndexParameters();
            var name = index.Length == 0
                ? property.Name
                : $"this[{FormatParameters(index)}]";
            members.Add(
                $"P: {Visibility(property)} {FormatType(property.PropertyType, SafeNullability(property))} {name} {{ {accessor}}}");
        }
        foreach (var @event in type.GetEvents(declared).Where(IsVisible))
        {
            members.Add(
                $"E: {Visibility(@event)} event {FormatType(@event.EventHandlerType ?? typeof(void), null)} {@event.Name}");
        }
        foreach (var method in type.GetMethods(declared)
            .Where(method => IsVisible(method) &&
                             !method.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false) &&
                             (!method.IsSpecialName || method.Name.StartsWith("op_", StringComparison.Ordinal))))
        {
            var modifiers = method.IsStatic ? "static " : method.IsAbstract ? "abstract " : method.IsVirtual && !method.IsFinal ? "virtual " : string.Empty;
            var genericArguments = method.IsGenericMethodDefinition
                ? $"<{string.Join(", ", method.GetGenericArguments().Select(argument => argument.Name))}>"
                : string.Empty;
            members.Add(
                $"M: {Visibility(method)} {modifiers}{FormatType(method.ReturnType, SafeNullability(method.ReturnParameter))} {method.Name}{genericArguments}({FormatParameters(method)}){FormatGenericConstraints(method.GetGenericArguments())}");
        }

        return members.Order(StringComparer.Ordinal);
    }

    private static string FormatTypeDeclaration(Type type)
    {
        var visibility = type.IsNested ? Visibility(type) : "public";
        if (type.IsEnum)
        {
            return $"T: {visibility} enum {TypeSortName(type)} : {FormatType(Enum.GetUnderlyingType(type), null)}";
        }
        if (typeof(MulticastDelegate).IsAssignableFrom(type.BaseType))
        {
            var invoke = type.GetMethod("Invoke", BindingFlags.Public | BindingFlags.Instance) ??
                throw new InvalidOperationException($"Delegate {type} has no Invoke method.");
            return $"T: {visibility} delegate {FormatType(invoke.ReturnType, SafeNullability(invoke.ReturnParameter))} {TypeSortName(type)}({FormatParameters(invoke)})";
        }

        var kind = type.IsInterface ? "interface" : type.IsValueType ? "struct" : "class";
        var modifiers = type.IsClass && type.IsAbstract && type.IsSealed
            ? "static "
            : type.IsClass && type.IsAbstract
                ? "abstract "
                : type.IsClass && type.IsSealed
                    ? "sealed "
                    : type.IsValueType && type.IsDefined(typeof(IsReadOnlyAttribute), inherit: false)
                        ? "readonly "
                        : string.Empty;
        var bases = new List<Type>();
        if (type.BaseType is not null && type.BaseType != typeof(object) &&
            type.BaseType != typeof(ValueType))
        {
            bases.Add(type.BaseType);
        }
        bases.AddRange(type.GetInterfaces().OrderBy(TypeSortName, StringComparer.Ordinal));
        var inheritance = bases.Count == 0
            ? string.Empty
            : $" : {string.Join(", ", bases.Select(baseType => FormatType(baseType, null)))}";
        return $"T: {visibility} {modifiers}{kind} {TypeSortName(type)}{inheritance}{FormatGenericConstraints(type.GetGenericArguments())}";
    }

    private static string FormatParameters(MethodBase method) => FormatParameters(method.GetParameters());

    private static string FormatParameters(ParameterInfo[] parameters)
    {
        var extensionMethod = parameters.Length != 0 &&
                              parameters[0].Member.IsDefined(typeof(ExtensionAttribute), inherit: false);
        return string.Join(", ", parameters.Select((parameter, index) =>
        {
            var prefix = index == 0 && extensionMethod ? "this " : string.Empty;
            if (parameter.IsDefined(typeof(ParamArrayAttribute), inherit: false)) prefix += "params ";
            var parameterType = parameter.ParameterType;
            if (parameterType.IsByRef)
            {
                prefix += parameter.IsOut ? "out " : parameter.IsIn ? "in " : "ref ";
                parameterType = parameterType.GetElementType() ??
                    throw new InvalidOperationException("By-ref parameter has no element type.");
            }
            var defaultValue = parameter.HasDefaultValue
                ? $" = {FormatConstant(parameter.DefaultValue, parameterType)}"
                : string.Empty;
            return $"{prefix}{FormatType(parameterType, SafeNullability(parameter))} {parameter.Name}{defaultValue}";
        }));
    }

    private static string FormatType(Type type, NullabilityInfo? nullability)
    {
        if (type == typeof(void)) return "System.Void";
        if (type.IsByRef) type = type.GetElementType()!;
        if (type.IsArray)
        {
            var rank = type.GetArrayRank() == 1 ? "[]" : $"[{new string(',', type.GetArrayRank() - 1)}]";
            return FormatType(type.GetElementType()!, nullability?.ElementType) + rank +
                   NullableSuffix(type, nullability);
        }
        if (Nullable.GetUnderlyingType(type) is { } nullableValue)
        {
            return FormatType(nullableValue, nullability?.GenericTypeArguments.FirstOrDefault()) + "?";
        }
        if (type.IsGenericParameter)
        {
            return type.Name + NullableSuffix(type, nullability);
        }
        if (type.IsGenericType)
        {
            var definitionName = TypeNameWithoutArity(type.GetGenericTypeDefinition());
            var arguments = type.GetGenericArguments();
            var nullableArguments = nullability?.GenericTypeArguments ?? [];
            var encodedArguments = arguments.Select((argument, index) =>
                FormatType(argument, index < nullableArguments.Length ? nullableArguments[index] : null));
            return $"{definitionName}<{string.Join(", ", encodedArguments)}>{NullableSuffix(type, nullability)}";
        }
        return TypeNameWithoutArity(type) + NullableSuffix(type, nullability);
    }

    private static string NullableSuffix(Type type, NullabilityInfo? nullability) =>
        !type.IsValueType && nullability?.ReadState == NullabilityState.Nullable ? "?" : string.Empty;

    private static string FormatGenericConstraints(Type[] arguments)
    {
        var constraints = new List<string>();
        foreach (var argument in arguments.Where(argument => argument.IsGenericParameter))
        {
            var values = new List<string>();
            var attributes = argument.GenericParameterAttributes;
            if ((attributes & GenericParameterAttributes.ReferenceTypeConstraint) != 0) values.Add("class");
            if ((attributes & GenericParameterAttributes.NotNullableValueTypeConstraint) != 0) values.Add("struct");
            values.AddRange(argument.GetGenericParameterConstraints().Select(type => FormatType(type, null)));
            if ((attributes & GenericParameterAttributes.DefaultConstructorConstraint) != 0 &&
                (attributes & GenericParameterAttributes.NotNullableValueTypeConstraint) == 0)
            {
                values.Add("new()");
            }
            if (values.Count != 0)
            {
                constraints.Add($" where {argument.Name} : {string.Join(", ", values)}");
            }
        }
        return string.Concat(constraints);
    }

    private static string FormatConstant(object? value, Type declaredType)
    {
        if (value is null || value is DBNull || value == Missing.Value) return "default";
        if (declaredType.IsEnum)
        {
            var name = Enum.GetName(declaredType, value);
            return name is null
                ? Convert.ToString(value, CultureInfo.InvariantCulture) ?? "0"
                : $"{TypeSortName(declaredType)}.{name}";
        }
        return value switch
        {
            string text => $"\"{text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)}\"",
            char character => $"'{character}'",
            bool boolean => boolean ? "true" : "false",
            float single => single.ToString("R", CultureInfo.InvariantCulture) + "F",
            double @double => @double.ToString("R", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "default",
        };
    }

    private static string TypeSortName(Type type) => TypeNameWithoutArity(type);

    private static string TypeNameWithoutArity(Type type)
    {
        var name = type.FullName ?? type.Name;
        name = name.Replace('+', '.');
        var tick = name.IndexOf('`');
        return tick < 0 ? name : name[..tick];
    }

    private static bool IsVisible(MethodBase method) =>
        method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly;

    private static bool IsVisible(FieldInfo field) =>
        field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly;

    private static bool IsVisible(PropertyInfo property) =>
        (property.GetGetMethod(nonPublic: true) is { } getter && IsVisible(getter)) ||
        (property.GetSetMethod(nonPublic: true) is { } setter && IsVisible(setter));

    private static bool IsVisible(EventInfo @event) =>
        (@event.AddMethod is { } add && IsVisible(add)) ||
        (@event.RemoveMethod is { } remove && IsVisible(remove));

    private static string Visibility(MethodBase method) => method.IsPublic
        ? "public"
        : method.IsFamilyOrAssembly
            ? "protected internal"
            : "protected";

    private static string Visibility(FieldInfo field) => field.IsPublic
        ? "public"
        : field.IsFamilyOrAssembly
            ? "protected internal"
            : "protected";

    private static string Visibility(PropertyInfo property)
    {
        var methods = new[] { property.GetGetMethod(true), property.GetSetMethod(true) }
            .Where(method => method is not null && IsVisible(method))
            .Cast<MethodInfo>();
        return Visibility(methods.OrderByDescending(VisibilityRank).First());
    }

    private static string Visibility(EventInfo @event)
    {
        var methods = new[] { @event.AddMethod, @event.RemoveMethod }
            .Where(method => method is not null && IsVisible(method))
            .Cast<MethodInfo>();
        return Visibility(methods.OrderByDescending(VisibilityRank).First());
    }

    private static string Visibility(Type type) => type.IsNestedPublic
        ? "public"
        : type.IsNestedFamORAssem
            ? "protected internal"
            : "protected";

    private static int VisibilityRank(MethodBase method) => method.IsPublic ? 3 : method.IsFamilyOrAssembly ? 2 : 1;

    private static NullabilityInfo? SafeNullability(ParameterInfo parameter)
    {
        try { return Nullability.Create(parameter); }
        catch (InvalidOperationException) { return null; }
    }

    private static NullabilityInfo? SafeNullability(PropertyInfo property)
    {
        try { return Nullability.Create(property); }
        catch (InvalidOperationException) { return null; }
    }

    private static NullabilityInfo? SafeNullability(FieldInfo field)
    {
        try { return Nullability.Create(field); }
        catch (InvalidOperationException) { return null; }
    }
}
