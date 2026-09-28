---
title: "Out of Band Authorization Code Delivery for OAuth 2.0"
abbrev: "OOB Auth Codes"
category: info

docname: draft-richer-oauth-oob-authcode-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - next generation
 - unicorn
 - AI-native
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "jricher/draft-richer-oauth-oob-authcode"
  latest: "https://jricher.github.io/draft-richer-oauth-oob-authcode/draft-richer-oauth-oob-authcode.html"

author:
 -
    fullname: Justin Richer
    organization: MongoDB
    email: ietf@justin.richer.org

normative:
  OAUTH: RFC6749
  HKDF: RFC5869
  BASE64: RFC4648
  SHA256: RFC6234

informative:
  DEVICECODE: RFC8628

...

--- abstract

This client-side process allows clients to use the authorization code grant type without the ability to host the redirect_uri themselves. This process creates a single copyable value that the resource owner can copy from a simple helper page into the waiting client application.

--- middle

# Introduction {#intro}

The OAuth authorization code grant type defined in {{OAUTH}} relies on the front-channel to communicate parameters between the client and authorization server (AS) using query parameters. This process relies on the resource owner's browser being able to launch a URI that is hosted on each of the AS and the client.

In some circumstances, such as a command line client running on a remote terminal, the resource owner's browser cannot reach a URL hosted by the client. These kinds of clients have traditionally used alternatives such as the device code grant type {{DEVICECODE}}, but the split between different grant types depending on where the client is running is a complication that requires server-side support, multiple network roundtrips (with polling), and potentially multiple different client registrations.

Instead of using a different grant type, an out-of-band mechanism, such as the resource owner copying and pasting values into the waiting client, to deliver the authorization code and state value from the AS to the client. This process can be error prone as multiple separate values need to be transferred intact to the client without having their values conflated with each other.

This specification defines a method to harden the out-of-band delivery of the `code` and `state` parameters to the client to be a single value that is less error-prone. No changes or participation by the AS is required (apart from a valid redirect_uri for the helper page).

## Terminology {#terminology}

{::boilerplate bcp14-tagged}

# Out of Band Authorization Code Transfer {#protocol}

~~~ aasvg

  +-----------+   +-----------+   +-----------+   +-----------+   +-----------+
  |    User   |   |   Client  |   |     AS    |   |  Browser  |   |   Helper  |
  +-----------+   +-----------+   +-----------+   +-----------+   +-----------+
        |               |               |               |               |
        |               |--(1)--------->|               |               |
        |               |               |               |               |
        |               |--(2)------------------------->|               |
        |               |               |               |               |
        |               |               |<-(3)----------|               |
        |               |               |               |               |
        |               |               |--(4)--------->|               |
        |               |               |               |               |
        |               |               |               |--(5)--------->|
        |               |               |               |               |
        |               |               |               |               |--+
        |               |               |               |               |  | (6)
        |               |               |               |               |<-+
        |               |               |               |               |
        |<-(7)----------------------------------------------------------|
        |               |               |               |               |
        |--(8)--------->|               |               |               |
        |               |               |               |               |
        |               |--+            |               |               |
        |               |  | (9)        |               |               |
        |               |<-+            |               |               |
        |               |               |               |               |
        |               |--(10)-------->|               |               |
        |               |               |               |               |

~~~

1. The client registers its helper page `https://c.example.com/callback` as a valid `redirect_uri`
2. The client creates a `state` value and sends it with other parameters to the browser as part of the authorization URI; the client waits for a paste input
3. The browser fetches the authorization URI at the AS
4. The AS completes the OAuth transaction and creates a `code` value and sends this to the browser as part of the callback
5. The browser fetches the helper page with the `code` and `state` parameters
6. The helper page parses the `code` and `state` parameters in javascript and calculates the combined code using HKDF in {{create}}
7. The user copies the combined code from the helper page
8. The user pastes the combined code into the client
9. The client uses its stored `state` value to derive the `code` value from the combined code in {{process}}
10. The client presents the derived `code` value to the token endpoint for an access token, along with other parmeters

Throughout this process, the client and AS need not have previously agreed on any shared secrets or encodings. The client does not start an HTTP server and does not receive the call to the redirect URI at all.

The client does need to know the value of the INFO parameter of the HKDF that the helper page uses and use the same value.

## Creating the Combined Code {#create}

The `state` and `code` values are combined using a HKDF function {{HKDF}} and a simple bytewise XOR.

```
1.  C  = UTF8(code)
2.  KS = HKDF(ikm  = UTF8(state),
              salt = "" (zero-length),
              info = INFO,
              L    = len(C)) ; always the same length as C
3.  E  = C ^ KS ; bytewise XOR
4.  T  = SHA256(C)[0..2] ; checksum
5.  CC = B64Uenc(T) || B64Uenc(E) ; concatenate the checksum
```

1. The `code` is translated to UTF8 bytes. Since the authorization code is ASCII per {{OAUTH}}, no additional encoding is needed for valid inputs.
2. The HKDF function creates a derived key based on the `state` value, the result that is exactly the same length as the `code` value.
3. The `code` value and the HKDF output are XORed together, bytewise, to create an encoded value E.
4. A 3-byte checksum is created by hashing the code value with {{SHA256}}.
5. The combined code CC is the concatenated checksum from (4) and the encoded value E from (3), both separately base64 URL encoded (with no padding). {{BASE64}}

The helper page MUST display the combined code value to the user.

## Processing the Combined Code {#process}

When the client receives the combined code, it uses its `state` value and extracts the `code` value for use at the AS.

```
1.  T' = B64Udec(CC[0..3])
2.  E  = B64Udec(CC[4..len(CC)])
3.  KS = HKDF(ikm  = UTF8(state),
              salt = "" (zero-length),
              info = INFO,
              L    = len(E))
4.  C = E ^ KS ; bytewise XOR
5.  T = SHA256(C)[0..2] ; checksum
6.  If T != T': FAIL
```

1. Extract the checksum as sent over the wire and decode it using Base64 URL with no padding {{BASE64}} into 3 bytes (4 Base64 chars).
2. Decode the remainder of the string into a byte array representing the encoded value E.
3. The HKDF function creates the derived key based on the `state` value, the result is exactly the same length as the encoded value E.
4. The combined code and the HKDF output are XORed together, bytewise, to extract the `code`.
5. A 3-byte checksum is created by hashing the extracted code value with {{SHA256}}.
6. If the checksum against the extracted code doesn't match the checksum sent over the wire, fail.

Any combined codes equal to or fewer than the checksum length (4 characters / 3 decoded bytes) MUST be discarded.

The client then uses the `code` value in its request to the token endpoint.

If the `state` value doesn't match, the key derivation will fail to produce a valid code, and the token request will fail.

# Limitations and Implementation Considerations {#implementation}

## Helper Page

The helper page is designed to be a statically hosted page with no backend processing and no state. Consequently, any person (or attacker) could use the same page to create combined codes using this algorithm by providing arbitrary `code` and `state` values. As such, the use of this does not protect clients from theft of `code` and `state` values.

## Stateless Clients

In order to use this, a client needs to know its `state` value at the time the request comes in. Stateless clients that depend on the `state` value to bootstrap the request won't be able to extract the `code` value from a combined code and shouldn't use this method.

## Fall-through For Static Pages {#fallthrough}

If the helper page is unable to process the HKDF calculation, such as JavaScript being disabled, the helper page SHOULD tell the user as much.

To support such cases, the client SHOULD additionally support the user copying and pasting the entire helper page URL, with parameters, and extracting the `code` and `state` values directly, just as if the client had served the URL itself. For this case, there is no use of the HKDF to create a combined code.

## Issuer Parameter

This process focuses only on the `code` and `state` parameters, and drops all other parameters including `iss`. This value could be used as the INFO parameter to the HKDF, but only if the client knows that the `iss` parameter is returned from the AS.

# Security Considerations {#security}

This process provides no additional security protections beyond that already provided by the basic authorization code grant. While cryptographic functions are used, the `code` value is still passed in the browser during the first steps and is not kept secret.

The `code` and `state` values are passed to whatever server, CDN, or system serves the static helper page, including its mirrors and caches, as part of the HTTP GET request.

The `state` value now needs to be cryptographically random enough to support the HKDF, and at the very least needs to be unique per request. Two identical (or guessable) state values could decode different codes on different requests.

# IANA Considerations {#iana}

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

Thank you to Jeff Lombardo for an early review of this work.
