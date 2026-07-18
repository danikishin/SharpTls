using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpTls.Certificates;
using SharpTls.IO;
using SharpTls.Protocol;
using SharpTls.Tests.Certificates;

namespace SharpTls.Tests;

public sealed class OptionsTests
{
    [Fact]
    public void RequiredCertificateEvidenceIsValidatorAndOfferBound()
    {
        Assert.Throws<ArgumentException>(() => new CustomTlsClientOptions
        {
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RequireValidStapledOcspResponse = true,
            },
        }.Snapshot());

        TlsServerCertificateEvidenceValidator validator = (_, _) =>
            ValueTask.FromResult(new TlsServerCertificateEvidenceValidationResult(
                TlsStapledOcspValidationStatus.Good,
                1));
        Assert.Throws<ArgumentException>(() => new CustomTlsClientOptions
        {
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                EvidenceValidator = validator,
                RequireValidStapledOcspResponse = true,
                MinimumValidSignedCertificateTimestamps = 1,
            },
        }.Snapshot());

        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.StatusRequest,
                    [1, 0, 0, 0, 0]),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.SignedCertificateTimestamp,
                    []),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        var options = new CustomTlsClientOptions
        {
            ClientHello = profile,
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                EvidenceValidator = validator,
                RequireValidStapledOcspResponse = true,
                MinimumValidSignedCertificateTimestamps = 1,
            },
        };

        using var snapshot = options.Snapshot();
        options.CertificateValidation.EvidenceValidator = null;
        options.CertificateValidation.MinimumValidSignedCertificateTimestamps = 0;

        Assert.Same(validator, snapshot.CertificateValidation.EvidenceValidator);
        Assert.True(snapshot.CertificateValidation.RequireValidStapledOcspResponse);
        Assert.Equal(
            1,
            snapshot.CertificateValidation.MinimumValidSignedCertificateTimestamps);
    }

    [Fact]
    public void ConstructionSnapshotIsIndependentOfCallerMutations()
    {
        using var pki = TestPki.Create();
        Action<TlsClientHelloInspection> originalInspector = _ => { };
        var options = new CustomTlsClientOptions
        {
            ServerName = "example.com",
            HandshakeFragmentation = new TlsRecordFragmentation(2_048, [1, 7]),
            Limits = new TlsLimits
            {
                MaxHandshakeMessageSize = 2 * 1024 * 1024,
                MaxCertificateListSize = 1024 * 1024,
                MaxCertificateCount = 8,
            },
            CertificateValidation = new CustomTlsCertificateValidationOptions
            {
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustRoots = [pki.Root],
            },
            ClientHelloInspector = originalInspector,
        };

        using var snapshot = options.Snapshot();
        options.ServerName = "mutated.invalid";
        options.Limits = new TlsLimits();
        options.CertificateValidation.RevocationMode = X509RevocationMode.Online;
        options.ClientHelloInspector = _ => throw new InvalidOperationException();

        Assert.Equal("example.com", snapshot.ServerName);
        Assert.Equal(2_048, snapshot.HandshakeFragmentation.MaximumFragmentSize);
        Assert.Equal(2 * 1024 * 1024, snapshot.Limits.MaxHandshakeMessageSize);
        Assert.Equal(X509RevocationMode.NoCheck, snapshot.CertificateValidation.RevocationMode);
        Assert.Same(originalInspector, snapshot.ClientHelloInspector);
        var clonedRoot = Assert.Single(snapshot.CertificateValidation.CustomTrustRoots!);
        Assert.NotSame(pki.Root, clonedRoot);
        Assert.Equal(pki.Root.RawData, clonedRoot.RawData);
    }

    [Fact]
    public void InvalidResourceLimitsAreRejectedBeforeNetworkIo()
    {
        var options = new CustomTlsClientOptions
        {
            Limits = new TlsLimits
            {
                MaxHandshakeMessageSize = 1_024,
                MaxCertificateListSize = 2_048,
            },
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => new CustomTlsClient(options));
    }

    [Fact]
    public void PaddingThatCannotFitAProtectedRecordIsRejected()
    {
        var options = new CustomTlsClientOptions
        {
            ApplicationDataPaddingLength = TlsConstants.MaxCiphertextLength,
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => new CustomTlsClient(options));
    }

    [Fact]
    public void Tls12ProfileRequiresEmsSecureRenegotiationAndExecutableAead()
    {
        var missingSecurityExtensions = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256));
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHello = missingSecurityExtensions,
        }));

        var cbcOnly = ClientHelloProfiles.Custom(builder => builder
            .WithLegacyTls12ClientHello()
            .WithCipherSuites(TlsCipherSuite.TlsEcdheRsaWithAes128CbcSha)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms)));
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHello = cbcOnly,
        }));
    }

    [Fact]
    public void Tls12OnlyProfileRejectsTls13ApplicationPadding()
    {
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHello = ClientHelloProfiles.UTlsAndroid11OkHttp,
            ApplicationDataPaddingLength = 1,
        }));
    }

    [Fact]
    public void EarlyDataRequiresReplayAcknowledgementCacheAndTls13OnlyProfile()
    {
        Assert.Throws<ArgumentException>(() =>
            new Tls13EarlyDataOptions([1], acknowledgeReplayRisk: false));

        var earlyData = new Tls13EarlyDataOptions([1], acknowledgeReplayRisk: true);
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            EarlyData = earlyData,
        }));

        using var cache = new Tls13SessionCache();
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            SessionCache = cache,
            EarlyData = earlyData,
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)
                .WithSessionResumption()
                .WithExtensionLayout(
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                    ClientHelloExtensionSpec.Raw(23, []),
                    ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PskKeyExchangeModes),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.EarlyData),
                    ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.PreSharedKey))),
        }));
    }

    [Fact]
    public void EarlyDataIsSnapshottedAndDefensivelyBounded()
    {
        using var cache = new Tls13SessionCache();
        var source = new byte[] { 1, 2, 3 };
        var earlyData = new Tls13EarlyDataOptions(source, acknowledgeReplayRisk: true);
        var options = new CustomTlsClientOptions
        {
            SessionCache = cache,
            EarlyData = earlyData,
        };
        using var snapshot = options.Snapshot();
        source[0] = 9;

        Assert.Equal(new byte[] { 1, 2, 3 }, snapshot.EarlyData!.Data.ToArray());

        options.Limits = new TlsLimits { MaxEarlyDataSize = 2 };
        Assert.Throws<ArgumentOutOfRangeException>(() => options.Snapshot());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    public void MaximumOfferedPskIdentityCountIsBounded(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new CustomTlsClientOptions
            {
                MaximumOfferedTls13PskIdentities = value,
            }.Snapshot());
    }

    [Fact]
    public void ClientApplicationSettingsAreDeeplySnapshotted()
    {
        var source = new byte[] { 1, 2, 3 };
        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("h2")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2"));
        var options = new CustomTlsClientOptions
        {
            ClientHello = profile,
            ClientApplicationSettings = new Dictionary<string, byte[]>
            {
                ["h2"] = source,
            },
        };

        using var snapshot = options.Snapshot();
        source[0] = 9;

        Assert.Equal(new byte[] { 1, 2, 3 }, snapshot.GetClientApplicationSettings("h2"));
        Assert.Empty(snapshot.GetClientApplicationSettings("missing"));
    }

    [Fact]
    public async Task ClientApplicationSettingsRejectUnadvertisedKeysAndAllowTicketBoundEarlyData()
    {
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientApplicationSettings = new Dictionary<string, byte[]> { ["h2"] = [] },
        }));

        var profile = ClientHelloProfiles.Custom(builder => builder
            .WithAlpn("h2")
            .WithApplicationSettings(TlsApplicationSettingsCodePoint.LegacyDraft, "h2")
            .WithSessionResumption());
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHello = profile,
            ClientApplicationSettings = new Dictionary<string, byte[]>
            {
                ["http/1.1"] = [],
            },
        }));

        using var cache = new Tls13SessionCache();
        await using var client = new CustomTlsClient(new CustomTlsClientOptions
        {
            ClientHello = profile,
            SessionCache = cache,
            EarlyData = new Tls13EarlyDataOptions([1], acknowledgeReplayRisk: true),
        });
    }

    [Fact]
    public void ProfileBoundGreaseEchIsSnapshottedWithoutCallerPlumbing()
    {
        using var snapshot = new CustomTlsClientOptions
        {
            ClientHello = ClientHelloProfiles.UTlsFirefox120,
        }.Snapshot();

        var grease = Assert.IsType<TlsEchGreaseConfiguration>(snapshot.EchGrease);
        Assert.Equal([223], Assert.IsType<int[]>(grease.PayloadLengths));
        Assert.Equal(2, grease.CipherSuites.Length);

        using var dynamicSnapshot = new CustomTlsClientOptions
        {
            ClientHello = ClientHelloProfiles.Custom(builder => builder
                .WithTls13()
                .WithGreaseEncryptedClientHello()),
        }.Snapshot();
        Assert.Null(dynamicSnapshot.EchGrease!.PayloadLengths);

        Assert.Throws<ArgumentOutOfRangeException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                EncryptedClientHelloGrease = new TlsEchGreaseOptions
                {
                    PayloadLengths = [ushort.MaxValue],
                },
            }));
        Assert.Throws<ArgumentOutOfRangeException>(() => ClientHelloProfiles.Custom(builder =>
            builder.WithTls13().WithGreaseEncryptedClientHello(
                Enumerable.Range(1, byte.MaxValue + 1).ToArray())));
    }

    [Fact]
    public void EchConfigurationIsDeeplySnapshottedAndSelectsExecutableHpke()
    {
        var encoded = CreateEchConfigList();
        var compressed = new[]
        {
            TlsExtensionType.SupportedGroups,
            TlsExtensionType.SignatureAlgorithms,
        };
        var options = new CustomTlsClientOptions
        {
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = TlsEchConfigList.Parse(encoded),
                CompressedOuterExtensions = compressed,
            },
        };

        using var snapshot = options.Snapshot();
        encoded[0] ^= 1;
        compressed[0] = TlsExtensionType.KeyShare;
        options.EncryptedClientHello.ConfigList =
            TlsEchConfigList.Parse([0, 4, 0x12, 0x34, 0, 0]);

        Assert.NotNull(snapshot.Ech);
        Assert.Equal("public.example", snapshot.Ech.Selection.Configuration.PublicName);
        Assert.Equal(TlsHpkeKemId.DhkemX25519HkdfSha256,
            snapshot.Ech.Selection.Configuration.KemId);
        Assert.Equal(TlsHpkeAeadId.Aes128Gcm,
            snapshot.Ech.Selection.CipherSuite.AeadId);
        Assert.Equal(
            new[] { TlsExtensionType.SupportedGroups, TlsExtensionType.SignatureAlgorithms },
            snapshot.Ech.CompressedOuterExtensions);
    }

    [Fact]
    public void EchRejectsUnsafeOrUnimplementedOptionCombinations()
    {
        var configList = TlsEchConfigList.Parse(CreateEchConfigList());
        using var cache = new Tls13SessionCache();
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                SessionCache = cache,
                EncryptedClientHello = new TlsEchOptions { ConfigList = configList },
            }));

        var mixedVersionInner = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedVersions(TlsProtocolVersion.Tls13, TlsProtocolVersion.Tls12)
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.Raw(23, []),
                ClientHelloExtensionSpec.Raw(0xFF01, [0]),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare)));
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                ClientHello = mixedVersionInner,
                EncryptedClientHello = new TlsEchOptions { ConfigList = configList },
            }));

        var narrowOuter = ClientHelloProfiles.Custom(builder => builder
            .WithSupportedGroups(NamedGroup.Secp256r1));
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                EncryptedClientHello = new TlsEchOptions
                {
                    ConfigList = configList,
                    OuterClientHello = narrowOuter,
                },
            }));

        var resumableProfile = ClientHelloProfiles.Custom(builder => builder
            .WithTls13()
            .WithSessionResumption());
        using (var snapshot = new CustomTlsClientOptions
        {
            ClientHello = resumableProfile,
            SessionCache = cache,
            EarlyData = new Tls13EarlyDataOptions(
                [1, 2, 3],
                acknowledgeReplayRisk: true),
            EncryptedClientHello = new TlsEchOptions
            {
                ConfigList = configList,
                OuterClientHello = resumableProfile,
            },
        }.Snapshot())
        {
            Assert.Equal(
                SHA256.HashData(configList.GetEncodedList()),
                snapshot.Ech!.ConfigListHash);
        }

        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                ClientHello = resumableProfile,
                SessionCache = cache,
                EncryptedClientHello = new TlsEchOptions
                {
                    ConfigList = configList,
                    OuterClientHello = resumableProfile,
                    CompressedOuterExtensions = [TlsExtensionType.PreSharedKey],
                },
            }));

        var unsupported = TlsEchConfigList.Parse([0, 4, 0x12, 0x34, 0, 0]);
        Assert.Throws<NotSupportedException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                EncryptedClientHello = new TlsEchOptions { ConfigList = unsupported },
            }));

        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                EncryptedClientHello = new TlsEchOptions
                {
                    ConfigList = configList,
                    CompressedOuterExtensions =
                    [TlsExtensionType.EncryptedClientHello],
                },
            }));

        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                EncryptedClientHello = new TlsEchOptions
                {
                    ConfigList = configList,
                    CompressedOuterExtensions =
                    [
                        TlsExtensionType.SupportedVersions,
                        TlsExtensionType.SupportedGroups,
                    ],
                },
            }));
    }

    [Fact]
    public void EchGreaseSuitesAreSnapshottedAndRealEchIsMutuallyExclusive()
    {
        var suites = new[]
        {
            new TlsHpkeSymmetricCipherSuite(
                TlsHpkeKdfId.HkdfSha256,
                TlsHpkeAeadId.Aes128Gcm),
        };
        var options = new CustomTlsClientOptions
        {
            EncryptedClientHelloGrease = new TlsEchGreaseOptions
            {
                CipherSuites = suites,
            },
        };

        using var snapshot = options.Snapshot();
        suites[0] = new TlsHpkeSymmetricCipherSuite(
            TlsHpkeKdfId.HkdfSha512,
            TlsHpkeAeadId.Aes256Gcm);

        Assert.NotNull(snapshot.EchGrease);
        Assert.Equal(TlsHpkeKdfId.HkdfSha256, snapshot.EchGrease.CipherSuites[0].KdfId);

        options.EncryptedClientHello = new TlsEchOptions
        {
            ConfigList = TlsEchConfigList.Parse(CreateEchConfigList()),
        };
        Assert.Throws<ArgumentException>(() => options.Snapshot());
    }

    [Fact]
    public void EchGreaseRejectsInvalidSuitesAndCallerOwnedEchExtension()
    {
        Assert.Throws<NotSupportedException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                EncryptedClientHelloGrease = new TlsEchGreaseOptions
                {
                    CipherSuites =
                    [
                        new TlsHpkeSymmetricCipherSuite(
                            (TlsHpkeKdfId)0xFFFF,
                            TlsHpkeAeadId.Aes128Gcm),
                    ],
                },
            }));

        var rawEch = ClientHelloProfiles.Custom(builder => builder
            .WithExtensionLayout(
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.ServerName),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedVersions),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SupportedGroups),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.SignatureAlgorithms),
                ClientHelloExtensionSpec.BuiltIn(ClientHelloExtensionKind.KeyShare),
                ClientHelloExtensionSpec.Raw(
                    (ushort)TlsExtensionType.EncryptedClientHello,
                    [0])));
        Assert.Throws<ArgumentException>(() => new CustomTlsClient(
            new CustomTlsClientOptions
            {
                ClientHello = rawEch,
                EncryptedClientHelloGrease = new TlsEchGreaseOptions(),
            }));
    }

    private static byte[] CreateEchConfigList()
    {
        var suites = new TlsBinaryWriter();
        suites.WriteUInt16((ushort)TlsHpkeKdfId.HkdfSha256);
        suites.WriteUInt16((ushort)TlsHpkeAeadId.Aes128Gcm);
        var contents = new TlsBinaryWriter();
        contents.WriteUInt8(7);
        contents.WriteUInt16((ushort)TlsHpkeKemId.DhkemX25519HkdfSha256);
        contents.WriteVector16(Convert.FromHexString(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"));
        contents.WriteVector16(suites.WrittenSpan);
        contents.WriteUInt8(0);
        contents.WriteVector8(Encoding.ASCII.GetBytes("public.example"));
        contents.WriteVector16([]);
        var configuration = new TlsBinaryWriter();
        configuration.WriteUInt16((ushort)TlsExtensionType.EncryptedClientHello);
        configuration.WriteVector16(contents.WrittenSpan);
        var list = new TlsBinaryWriter();
        list.WriteVector16(configuration.WrittenSpan);
        return list.ToArray();
    }
}
