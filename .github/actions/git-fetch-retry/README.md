# git-fetch-retry

Composite action wrapping `git fetch` with HTTP/1.1 and bounded exponential
backoff. Durable follow-up to the runner-side global git config; use where a job
needs an `--unshallow` or extra fetch that has been observed to flake with
`curl 56` / `curl 92 HTTP/2 stream CANCEL` on the self-hosted Linux runners.

## Use

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: ./.github/actions/git-fetch-retry
  with:
    args: "--unshallow"
    retries: "5"
```

## Runner-side config (applied out-of-band on 198-1/-2/-3)

```
git config --global http.version HTTP/1.1
git config --global http.postBuffer 524288000
git config --global http.lowSpeedLimit 1000
git config --global http.lowSpeedTime 300
```

Revert (per host): `for k in version postBuffer lowSpeedLimit lowSpeedTime; do git config --global --unset http.$k; done`
