//! Trie-backed IP prefix lookup for cloud service ranges.
//!
//! Uses [`prefix_trie::PrefixMap`] for O(log n) longest-prefix-match lookups on
//! ~9,000 cloud provider IP prefixes. Available only with the `std` feature.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use prefix_trie::PrefixMap;

use crate::cloud::CloudProvider;

/// Metadata associated with a service IP range entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    /// The cloud provider that owns this range.
    pub provider: CloudProvider,
    /// The service name within that provider (e.g. "EC2", "S3").
    pub service: String,
}

/// A trie-backed table for efficient IP-to-service lookups.
///
/// Supports both IPv4 and IPv6 prefixes in separate tries for optimal performance.
#[derive(Debug)]
pub struct ServiceRangeTable {
    v4: PrefixMap<ipnet::Ipv4Net, ServiceInfo>,
    v6: PrefixMap<ipnet::Ipv6Net, ServiceInfo>,
}

impl ServiceRangeTable {
    /// Create an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        }
    }

    /// Load service ranges from a single `domains_*.json` file.
    ///
    /// Reads the `service_ranges.prefixes` field from the JSON and inserts all
    /// valid CIDRs into the trie. The provider is inferred from the `provider`
    /// field in the JSON.
    pub fn load_from_file(path: &Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::Error::Config(alloc::format!("failed to read {}: {e}", path.display()))
        })?;
        let data: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            crate::Error::Config(alloc::format!("failed to parse {}: {e}", path.display()))
        })?;
        let provider = match data["provider"].as_str().unwrap_or("") {
            "aws" => CloudProvider::Aws,
            "azure" => CloudProvider::Azure,
            "gcp" => CloudProvider::Gcp,
            other => {
                return Err(crate::Error::Config(alloc::format!(
                    "unknown provider '{other}' in {}",
                    path.display()
                )));
            }
        };

        let mut table = Self::new();
        if let Some(prefixes_obj) = data["service_ranges"]["prefixes"].as_object() {
            let prefixes: HashMap<String, Vec<String>> = prefixes_obj
                .iter()
                .map(|(k, v)| {
                    let cidrs = v
                        .as_array()
                        .unwrap_or(&Vec::new())
                        .iter()
                        .filter_map(|c| c.as_str().map(String::from))
                        .collect();
                    (k.clone(), cidrs)
                })
                .collect();
            table.load(provider, &prefixes);
        }
        Ok(table)
    }

    /// Load and merge all three provider files from a config directory.
    ///
    /// Expects `domains_aws.json`, `domains_azure.json`, and `domains_gcp.json`
    /// in the given directory.
    pub fn load_all(config_dir: &Path) -> crate::Result<Self> {
        let mut table = Self::new();
        for provider in &["aws", "azure", "gcp"] {
            let path = config_dir.join(format!("domains_{provider}.json"));
            if !path.exists() {
                continue;
            }
            let single = Self::load_from_file(&path)?;
            table.merge(single);
        }
        Ok(table)
    }

    /// Load service ranges from an in-memory map (keyed by service name).
    ///
    /// Invalid CIDRs are silently skipped.
    pub fn load(&mut self, provider: CloudProvider, prefixes: &HashMap<String, Vec<String>>) {
        for (service, cidrs) in prefixes {
            let info = ServiceInfo {
                provider,
                service: service.clone(),
            };
            for cidr_str in cidrs {
                match cidr_str.parse::<IpNet>() {
                    Ok(IpNet::V4(net)) => {
                        self.v4.insert(net, info.clone());
                    }
                    Ok(IpNet::V6(net)) => {
                        self.v6.insert(net, info.clone());
                    }
                    Err(_) => {}
                }
            }
        }
    }

    /// Merge another table into this one.
    pub fn merge(&mut self, other: Self) {
        for (prefix, info) in other.v4 {
            self.v4.insert(prefix, info);
        }
        for (prefix, info) in other.v6 {
            self.v6.insert(prefix, info);
        }
    }

    /// O(log n) longest-prefix-match: which cloud service owns this IP?
    #[must_use]
    pub fn lookup(&self, addr: IpAddr) -> Option<&ServiceInfo> {
        match addr {
            IpAddr::V4(v4) => {
                let host_net = ipnet::Ipv4Net::new(v4, 32).ok()?;
                self.v4.get_lpm(&host_net).map(|(_, info)| info)
            }
            IpAddr::V6(v6) => {
                let host_net = ipnet::Ipv6Net::new(v6, 128).ok()?;
                self.v6.get_lpm(&host_net).map(|(_, info)| info)
            }
        }
    }

    /// Simple membership test: is this IP in any known service range?
    #[must_use]
    pub fn is_service_ip(&self, addr: IpAddr) -> bool {
        self.lookup(addr).is_some()
    }

    /// Total number of prefixes in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Returns true if the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ServiceRangeTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_returns_none() {
        let table = ServiceRangeTable::new();
        assert!(table.lookup("10.0.0.1".parse().unwrap()).is_none());
        assert!(!table.is_service_ip("10.0.0.1".parse().unwrap()));
        assert!(table.is_empty());
    }

    #[test]
    fn load_and_lookup_ipv4() {
        let mut table = ServiceRangeTable::new();
        let mut prefixes = HashMap::new();
        prefixes.insert(
            "EC2".to_string(),
            vec!["3.5.140.0/22".to_string(), "52.94.76.0/22".to_string()],
        );
        prefixes.insert("S3".to_string(), vec!["52.217.0.0/16".to_string()]);

        table.load(CloudProvider::Aws, &prefixes);

        let info = table.lookup("3.5.140.1".parse().unwrap()).unwrap();
        assert_eq!(info.provider, CloudProvider::Aws);
        assert_eq!(info.service, "EC2");

        let info = table.lookup("52.217.100.5".parse().unwrap()).unwrap();
        assert_eq!(info.service, "S3");

        assert!(table.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(table.is_service_ip("3.5.140.1".parse().unwrap()));
        assert!(!table.is_service_ip("8.8.8.8".parse().unwrap()));
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn load_and_lookup_ipv6() {
        let mut table = ServiceRangeTable::new();
        let mut prefixes = HashMap::new();
        prefixes.insert("CLOUD".to_string(), vec!["2600:1900::/28".to_string()]);

        table.load(CloudProvider::Gcp, &prefixes);

        let info = table.lookup("2600:1900::1".parse().unwrap()).unwrap();
        assert_eq!(info.provider, CloudProvider::Gcp);
        assert_eq!(info.service, "CLOUD");

        assert!(table.lookup("2001:db8::1".parse().unwrap()).is_none());
    }

    #[test]
    fn longest_prefix_match() {
        let mut table = ServiceRangeTable::new();
        let mut prefixes = HashMap::new();
        prefixes.insert("GENERAL".to_string(), vec!["10.0.0.0/8".to_string()]);
        prefixes.insert("SPECIFIC".to_string(), vec!["10.0.1.0/24".to_string()]);
        table.load(CloudProvider::Aws, &prefixes);

        let info = table.lookup("10.0.1.5".parse().unwrap()).unwrap();
        assert_eq!(info.service, "SPECIFIC");

        let info = table.lookup("10.0.2.5".parse().unwrap()).unwrap();
        assert_eq!(info.service, "GENERAL");
    }

    #[test]
    fn merge_tables() {
        let mut table_a = ServiceRangeTable::new();
        let mut prefixes_a = HashMap::new();
        prefixes_a.insert("EC2".to_string(), vec!["3.5.140.0/22".to_string()]);
        table_a.load(CloudProvider::Aws, &prefixes_a);

        let mut table_b = ServiceRangeTable::new();
        let mut prefixes_b = HashMap::new();
        prefixes_b.insert("CLOUD".to_string(), vec!["34.80.0.0/15".to_string()]);
        table_b.load(CloudProvider::Gcp, &prefixes_b);

        table_a.merge(table_b);
        assert_eq!(table_a.len(), 2);
        assert_eq!(
            table_a
                .lookup("3.5.140.1".parse().unwrap())
                .unwrap()
                .provider,
            CloudProvider::Aws
        );
        assert_eq!(
            table_a
                .lookup("34.80.0.1".parse().unwrap())
                .unwrap()
                .provider,
            CloudProvider::Gcp
        );
    }

    #[test]
    fn load_all_from_config_dir() {
        let config_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config");
        let table = ServiceRangeTable::load_all(&config_dir).unwrap();
        // The table may be populated or empty depending on whether the codegen
        // script has run. Just verify it loads without error and basic lookups work.
        if !table.is_empty() {
            assert!(!table.is_service_ip("127.0.0.1".parse().unwrap()));
        }
    }
}
