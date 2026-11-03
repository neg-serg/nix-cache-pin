//! Default clients keep HTTP usable when a runtime has no platform trust store.

use reqwest::redirect::Policy;

/// Redirect hops a default client follows before giving up, matching reqwest.
///
/// Reqwest counts the initial URL in `Attempt::previous`, so the tenth hop is
/// still followed and the eleventh is refused.
const MAX_REDIRECTS: usize = 10;

/// Refuse a redirect hop that would reach the compromised cache or run past
/// the hop limit; `previous` counts the initial URL plus every followed hop.
fn redirect_refusal(url: &reqwest::Url, previous: usize) -> Option<String> {
    if crate::config::is_compromised_url(url) {
        let host = url.host_str().unwrap_or("the cache");
        return Some(format!(
            "refusing redirect to {host}: that cache was compromised (https://github.com/xddxdd/nix-cachyos-kernel/issues/110)"
        ));
    }
    (previous > MAX_REDIRECTS).then(|| "too many redirects".to_string())
}

/// Re-check every redirect hop before the request is sent.
///
/// The narinfo lookup rejects a configured cache on the compromised host, but a
/// mirror can answer with a redirect; following it would contact that host
/// anyway. Reqwest runs this policy before each hop, so the banned endpoint is
/// never reached.
fn redirect_policy() -> Policy {
    Policy::custom(
        |attempt| match redirect_refusal(attempt.url(), attempt.previous().len()) {
            Some(reason) => attempt.error(reason),
            None => attempt.follow(),
        },
    )
}

/// Build the default client with the cache redirect policy installed.
///
/// Use this when an embedder needs extra settings (private roots, proxies,
/// resolver overrides) but still wants lookups to refuse a compromised cache.
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().redirect(redirect_policy())
}

/// Build a default client without panicking on unavailable platform roots.
///
/// Platform verification remains the first choice. If initialization fails,
/// retry with an empty explicit trust store: plain HTTP still works, while
/// HTTPS cannot authenticate any server certificate. This never disables
/// certificate or hostname verification. Other initialization failures remain
/// ordinary errors. Callers with private roots can still inject their own client.
pub fn client() -> crate::error::Result<reqwest::Client> {
    Ok(client_builder()
        .build()
        .or_else(|_| client_builder().tls_certs_only(std::iter::empty()).build())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> reqwest::Url {
        reqwest::Url::parse(raw).unwrap()
    }

    #[test]
    fn refuses_redirects_to_the_compromised_host() {
        for target in [
            "https://attic.xuyh0120.win/lantian",
            "https://attic%2exuyh0120.win/lantian",
            "https://mirror.ATTIC.xuyh0120.win/lantian",
            "https://attic.xuyh0120.win./lantian",
        ] {
            let reason = redirect_refusal(&url(target), 1);
            assert!(reason.is_some(), "{target} was followed");
            assert!(
                reason.unwrap().contains("compromised"),
                "{target} was refused for the wrong reason"
            );
        }
    }

    #[test]
    fn follows_redirects_to_trusted_hosts_within_the_limit() {
        for target in [
            "https://cache.nixos.org/lantian",
            "https://cache.nixos.org/attic.xuyh0120.win",
            "https://evil.example@attic.example.org/x",
        ] {
            assert!(
                redirect_refusal(&url(target), 1).is_none(),
                "{target} was refused"
            );
        }
        let trusted = url("https://cache.nixos.org/x");
        assert!(redirect_refusal(&trusted, MAX_REDIRECTS).is_none());
        assert!(redirect_refusal(&trusted, MAX_REDIRECTS + 1).is_some());
    }
}
