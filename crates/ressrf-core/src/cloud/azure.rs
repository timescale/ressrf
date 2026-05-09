//! Azure cloud module: IMDS/Wireserver deny ranges and domain suffixes.

/// Tier 2 deny ranges for Azure metadata endpoints.
pub const DENY_RANGES: &[&str] = &[
    "169.254.169.254/32", // IMDS
    "168.63.129.16/32",   // Wireserver / DHCP
];

/// Tier 4a: Internal DNS suffixes to deny.
pub const DENIED_DOMAIN_SUFFIXES: &[&str] = &[".internal.cloudapp.net"];

/// Tier 4b: Azure service domain suffixes (for trusted-domain allow usage).
pub const SERVICE_DOMAIN_SUFFIXES: &[&str] = &[
    ".core.windows.net",
    ".vault.azure.net",
    ".database.windows.net",
    ".azurecr.io",
    ".servicebus.windows.net",
    ".documents.azure.com",
    // Sovereign clouds
    ".core.chinacloudapi.cn",
    ".vault.azure.cn",
    ".core.cloudapi.de",
    ".core.usgovcloudapi.net",
];
