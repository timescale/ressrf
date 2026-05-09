use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ressrf_core::{
    cidr::{Cidr, CidrSet},
    error::DataTier,
    policy::PolicyBuilder,
    uri_validator::UriValidator,
};

fn bench_cidr_parse(c: &mut Criterion) {
    c.bench_function("cidr_parse_v4", |b| {
        b.iter(|| Cidr::parse(black_box("10.0.0.0/8"), DataTier::Iana));
    });
    c.bench_function("cidr_parse_v6", |b| {
        b.iter(|| Cidr::parse(black_box("fd00::/8"), DataTier::Iana));
    });
}

fn bench_cidr_contains(c: &mut Criterion) {
    let cidr = Cidr::parse("10.0.0.0/8", DataTier::Iana).unwrap();
    let ip_match: IpAddr = Ipv4Addr::new(10, 1, 2, 3).into();
    let ip_miss: IpAddr = Ipv4Addr::new(93, 184, 216, 34).into();

    c.bench_function("cidr_contains_hit", |b| {
        b.iter(|| cidr.contains(black_box(ip_match)));
    });
    c.bench_function("cidr_contains_miss", |b| {
        b.iter(|| cidr.contains(black_box(ip_miss)));
    });
}

fn bench_cidr_set_lookup(c: &mut Criterion) {
    let mut set = CidrSet::new();
    for s in &[
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "fd00::/8",
        "fe80::/10",
        "::1/128",
    ] {
        set.add(Cidr::parse(s, DataTier::Iana).unwrap());
    }

    let ip_hit: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
    let ip_miss: IpAddr = Ipv4Addr::new(93, 184, 216, 34).into();
    let ip_v6_hit: IpAddr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into();

    c.bench_function("cidr_set_lookup_hit", |b| {
        b.iter(|| set.contains(black_box(ip_hit)));
    });
    c.bench_function("cidr_set_lookup_miss", |b| {
        b.iter(|| set.contains(black_box(ip_miss)));
    });
    c.bench_function("cidr_set_lookup_v6_hit", |b| {
        b.iter(|| set.contains(black_box(ip_v6_hit)));
    });
}

fn bench_policy_build(c: &mut Criterion) {
    c.bench_function("policy_build_external_only", |b| {
        b.iter(|| {
            let mut builder = PolicyBuilder::external_only();
            builder.add_denied(&["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
            builder.build()
        });
    });
}

fn bench_policy_is_network_allowed(c: &mut Criterion) {
    let mut builder = PolicyBuilder::external_only();
    builder.add_denied(&["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
    let policy = builder.build();

    let allowed_ips: Vec<IpAddr> = vec![Ipv4Addr::new(93, 184, 216, 34).into()];
    let blocked_ips: Vec<IpAddr> = vec![Ipv4Addr::new(10, 0, 0, 1).into()];

    c.bench_function("policy_network_allowed", |b| {
        b.iter(|| policy.is_network_allowed(black_box(&allowed_ips)));
    });
    c.bench_function("policy_network_blocked", |b| {
        b.iter(|| policy.is_network_allowed(black_box(&blocked_ips)));
    });
}

fn bench_uri_validator(c: &mut Criterion) {
    let validator = UriValidator::new();
    let mut builder = PolicyBuilder::external_only();
    builder.add_denied(&["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
    let policy = builder.build();

    c.bench_function("uri_validate_allowed", |b| {
        b.iter(|| {
            validator.validate_url(
                black_box("https://example.com/api/v1/resource"),
                Some(&policy),
            )
        });
    });
    c.bench_function("uri_validate_bare_ip_blocked", |b| {
        b.iter(|| validator.validate_url(black_box("http://192.168.1.1/admin"), Some(&policy)));
    });
    c.bench_function("uri_validate_no_policy", |b| {
        b.iter(|| validator.validate_url(black_box("https://example.com/path?q=1"), None));
    });
}

criterion_group!(
    benches,
    bench_cidr_parse,
    bench_cidr_contains,
    bench_cidr_set_lookup,
    bench_policy_build,
    bench_policy_is_network_allowed,
    bench_uri_validator,
);
criterion_main!(benches);
