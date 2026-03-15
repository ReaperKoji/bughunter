# Report: Missing X-Frame-Options on Profile Page

## Summary
The authenticated profile page is missing the `X-Frame-Options` header. This allows clickjacking risk if combined with social engineering.

## Steps to Reproduce (Safe)
1. Authenticate normally.
2. Request the profile page.

```bash
curl -i -H "Authorization: Bearer [REDACTED]" "https://app.example.com/profile"
```

## Evidence (Sanitized)
```
HTTP/1.1 200 OK
content-type: text/html; charset=utf-8
```

## Impact
Potential clickjacking on sensitive profile actions if a user is tricked into interacting with a hidden frame.

## Recommendation
Add `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'` policy.

## Notes
All tokens were redacted. No destructive testing performed.
