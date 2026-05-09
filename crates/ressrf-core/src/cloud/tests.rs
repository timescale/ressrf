use crate::cidr::Cidr;
use crate::cloud::{aws, azure, gcp, CloudProvider};
use crate::error::DataTier;
use crate::policy::PolicyBuilder;
use crate::uri_validator::UriValidator;
use std::net::IpAddr;

#[test]
fn aws_deny_ranges_parse() {
    for range in aws::DENY_RANGES {
        assert!(
            Cidr::parse(range, DataTier::CloudAws).is_ok(),
            "failed to parse AWS deny range: {range}"
        );
    }
}

#[test]
fn azure_deny_ranges_parse() {
    for range in azure::DENY_RANGES {
        assert!(
            Cidr::parse(range, DataTier::CloudAzure).is_ok(),
            "failed to parse Azure deny range: {range}"
        );
    }
}

#[test]
fn gcp_deny_ranges_parse() {
    for range in gcp::DENY_RANGES {
        assert!(
            Cidr::parse(range, DataTier::CloudGcp).is_ok(),
            "failed to parse GCP deny range: {range}"
        );
    }
}

#[test]
fn aws_blocks_imds_ipv4() {
    let mut builder = PolicyBuilder::external_only();
    builder.with_cloud(CloudProvider::Aws);
    let policy = builder.build();
    let imds: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(policy.is_network_allowed(&[imds]).is_err());
}

#[test]
fn aws_blocks_imds_ipv6() {
    let mut builder = PolicyBuilder::external_only();
    builder.with_cloud(CloudProvider::Aws);
    let policy = builder.build();
    let imds_v6: IpAddr = "fd00:ec2::254".parse().unwrap();
    assert!(policy.is_network_allowed(&[imds_v6]).is_err());
}

#[test]
fn aws_blocks_ecs_metadata() {
    let mut builder = PolicyBuilder::external_only();
    builder.with_cloud(CloudProvider::Aws);
    let policy = builder.build();
    let ecs: IpAddr = "169.254.170.2".parse().unwrap();
    assert!(policy.is_network_allowed(&[ecs]).is_err());
}

#[test]
fn azure_blocks_wireserver() {
    let mut builder = PolicyBuilder::external_only();
    builder.with_cloud(CloudProvider::Azure);
    let policy = builder.build();
    let wireserver: IpAddr = "168.63.129.16".parse().unwrap();
    assert!(policy.is_network_allowed(&[wireserver]).is_err());
}

#[test]
fn gcp_blocks_metadata() {
    let mut builder = PolicyBuilder::external_only();
    builder.with_cloud(CloudProvider::Gcp);
    let policy = builder.build();
    let metadata: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(policy.is_network_allowed(&[metadata]).is_err());
}

#[test]
fn cloud_provider_allows_public_ip() {
    for provider in [CloudProvider::Aws, CloudProvider::Azure, CloudProvider::Gcp] {
        let mut builder = PolicyBuilder::external_only();
        builder.with_cloud(provider);
        let policy = builder.build();
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(
            policy.is_network_allowed(&[public]).is_ok(),
            "{provider:?} should allow public IP"
        );
    }
}

#[test]
fn aws_denied_domain_suffixes() {
    let mut validator = UriValidator::new();
    validator.with_cloud_provider(CloudProvider::Aws);
    let result = validator.validate_url("https://secret.ec2.internal/foo", None);
    assert!(result.is_err());
}

#[test]
fn azure_denied_domain_suffixes() {
    let mut validator = UriValidator::new();
    validator.with_cloud_provider(CloudProvider::Azure);
    let result = validator.validate_url("https://vm1.internal.cloudapp.net/metadata", None);
    assert!(result.is_err());
}

#[test]
fn gcp_denied_domain_suffixes() {
    let mut validator = UriValidator::new();
    validator.with_cloud_provider(CloudProvider::Gcp);
    let result = validator.validate_url("https://host.internal/secret", None);
    assert!(result.is_err());
}

#[test]
fn aws_trusted_service_domains_allowed() {
    let mut validator = UriValidator::new();
    validator.with_cloud_provider(CloudProvider::Aws);
    let result = validator.validate_url("https://s3.amazonaws.com/bucket/key", None);
    assert!(result.is_ok());
}

#[test]
fn azure_trusted_service_domains_allowed() {
    let mut validator = UriValidator::new();
    validator.with_cloud_provider(CloudProvider::Azure);
    let result = validator.validate_url("https://mystuff.core.windows.net/blob", None);
    assert!(result.is_ok());
}

#[test]
fn gcp_trusted_service_domains_allowed() {
    let mut validator = UriValidator::new();
    validator.with_cloud_provider(CloudProvider::Gcp);
    let result = validator.validate_url("https://storage.googleapis.com/bucket", None);
    assert!(result.is_ok());
}

#[test]
fn cloud_provider_names() {
    assert_eq!(CloudProvider::Aws.name(), "aws");
    assert_eq!(CloudProvider::Azure.name(), "azure");
    assert_eq!(CloudProvider::Gcp.name(), "gcp");
}

#[test]
fn denied_suffixes_are_nonempty() {
    for provider in [CloudProvider::Aws, CloudProvider::Azure, CloudProvider::Gcp] {
        assert!(
            !provider.denied_domain_suffixes().is_empty(),
            "{provider:?} should have denied domain suffixes"
        );
    }
}

#[test]
fn service_suffixes_are_nonempty() {
    for provider in [CloudProvider::Aws, CloudProvider::Azure, CloudProvider::Gcp] {
        assert!(
            !provider.service_domain_suffixes().is_empty(),
            "{provider:?} should have service domain suffixes"
        );
    }
}
