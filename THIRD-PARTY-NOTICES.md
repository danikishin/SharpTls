# Third-party notices

## SharpFuzz development harness

The optional `tools/SharpTls.CoverageFuzz` development project references SharpFuzz
2.3.0 to connect SharpTls's bounded fuzz targets to libFuzzer coverage feedback.
SharpFuzz is not referenced by, copied into, or distributed with the SharpTls NuGet
package. It is available under the MIT License from
`https://github.com/Metalnem/sharpfuzz`.

The hosted coverage job compiles the Linux driver source from
`https://github.com/Metalnem/libfuzzer-dotnet` at commit
`bd39d4e88d715ab460a929943645be2a186cde52`. The source is SHA-256 verified before
compilation and is used only by the development workflow; neither source nor binary is
distributed in the SharpTls package. libfuzzer-dotnet is available under the MIT License.

## refraction-networking/uTLS profile specifications

SharpTls includes independently encoded C# ClientHello profile data derived from the
`UTLSIdToSpec` tables in refraction-networking/uTLS, pinned at commit
`880e27d8b0e5daafd2a39bb3fb2e0c29211c0d40`. No Go TLS implementation is embedded or
called by SharpTls.

The upstream repository distributes this material under the following BSD 3-Clause
license:

> Copyright (c) 2009 The Go Authors. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification,
> are permitted provided that the following conditions are met:
>
> - Redistributions of source code must retain the above copyright notice, this list
>   of conditions and the following disclaimer.
> - Redistributions in binary form must reproduce the above copyright notice, this
>   list of conditions and the following disclaimer in the documentation and/or other
>   materials provided with the distribution.
> - Neither the name of Google Inc. nor the names of its contributors may be used to
>   endorse or promote products derived from this software without specific prior
>   written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
> EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
> OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
> SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
> INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
> LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
> PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
> WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

## Go standard library FIPS 202 and FIPS 203 implementations

`src/SharpTls/Cryptography/Fips202.cs`, `MlKem768.cs`, and
`MlKem768.Field.cs` are C# ports and adaptations of the Go standard library's
FIPS 140 SHA-3 and ML-KEM implementation. The source files retain their copyright
headers. The upstream Go source is distributed under the following license:

> Copyright 2009 The Go Authors.
>
> Redistribution and use in source and binary forms, with or without modification,
> are permitted provided that the following conditions are met:
>
> - Redistributions of source code must retain the above copyright notice, this list
>   of conditions and the following disclaimer.
> - Redistributions in binary form must reproduce the above copyright notice, this
>   list of conditions and the following disclaimer in the documentation and/or other
>   materials provided with the distribution.
> - Neither the name of Google LLC nor the names of its contributors may be used to
>   endorse or promote products derived from this software without specific prior
>   written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
> EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
> OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
> SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
> INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
> LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
> PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
> WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.
