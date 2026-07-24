//! Open vocabulary tables (unknown values are extensions).
//!
//! Generated from STIX 2.1 §10 normative value tables in `plan/stix-v2.1-spec.md`.

/// Account type open vocabulary.
pub static ACCOUNT_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "facebook", "ldap", "nis", "openid", "radius", "skype", "tacacs", "twitter", "unix",
    "windows-domain", "windows-local"
};

/// Attack motivation open vocabulary.
pub static ATTACK_MOTIVATION_OV: phf::Set<&'static str> = phf::phf_set! {
    "accidental", "coercion", "dominance", "ideology", "notoriety", "organizational-gain",
    "personal-gain", "personal-satisfaction", "revenge", "unpredictable"
};

/// Attack resource level open vocabulary.
pub static ATTACK_RESOURCE_LEVEL_OV: phf::Set<&'static str> =
    phf::phf_set! { "club", "contest", "government", "individual", "organization", "team" };

/// Grouping context open vocabulary.
pub static GROUPING_CONTEXT_OV: phf::Set<&'static str> =
    phf::phf_set! { "malware-analysis", "suspicious-activity", "unspecified" };

/// Identity class open vocabulary.
pub static IDENTITY_CLASS_OV: phf::Set<&'static str> =
    phf::phf_set! { "class", "group", "individual", "organization", "system", "unknown" };

/// Implementation language open vocabulary.
pub static IMPLEMENTATION_LANGUAGE_OV: phf::Set<&'static str> = phf::phf_set! {
    "applescript", "bash", "c", "c#", "c++", "go", "java", "javascript", "lua", "objective-c",
    "perl", "php", "powershell", "python", "ruby", "rust", "scala", "swift", "typescript",
    "visual-basic", "x86-32", "x86-64"
};

/// Indicator type open vocabulary.
pub static INDICATOR_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "anomalous-activity", "anonymization", "attribution", "benign", "compromised",
    "malicious-activity", "unknown"
};

/// Industry sector open vocabulary.
pub static INDUSTRY_SECTOR_OV: phf::Set<&'static str> = phf::phf_set! {
    "aerospace", "agriculture", "automotive", "chemical", "commercial", "communications",
    "construction", "dams", "defense", "education", "emergency-services", "energy", "entertainment",
    "financial-services", "government", "government-local", "government-national",
    "government-public-services", "government-regional", "healthcare", "hospitality-leisure",
    "infrastructure", "insurance", "legal", "manufacturing", "mining", "non-profit", "nuclear",
    "pharmaceuticals", "retail", "technology", "telecommunications", "transportation", "utilities",
    "water"
};

/// Infrastructure type open vocabulary.
pub static INFRASTRUCTURE_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "amplification", "anonymization", "botnet", "command-and-control", "control-system",
    "exfiltration", "firewall", "hosting-malware", "hosting-target-lists", "phishing",
    "reconnaissance", "routers-switches", "staging", "unknown", "workstation"
};

/// Malware capabilities open vocabulary.
pub static MALWARE_CAPABILITIES_OV: phf::Set<&'static str> = phf::phf_set! {
    "accesses-remote-machines", "anti-debugging", "anti-disassembly", "anti-emulation",
    "anti-memory-forensics", "anti-sandbox", "anti-vm", "captures-input-peripherals",
    "captures-output-peripherals", "captures-system-state-data", "cleans-traces-of-infection",
    "commits-fraud", "communicates-with-c2", "compromises-data-availability",
    "compromises-data-integrity", "compromises-system-availability", "controls-local-machine",
    "degrades-security-software", "degrades-system-updates", "determines-c2-server", "emails-spam",
    "escalates-privileges", "evades-av", "exfiltrates-data", "fingerprints-host", "hides-artifacts",
    "hides-executing-code", "infects-files", "infects-remote-machines", "installs-other-components",
    "persists-after-system-reboot", "prevents-artifact-access", "prevents-artifact-deletion",
    "probes-network-environment", "self-modifies", "steals-authentication-credentials",
    "violates-system-operational-integrity"
};

/// Malware type open vocabulary.
pub static MALWARE_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "adware", "backdoor", "bootkit", "bot", "ddos", "downloader", "dropper", "exploit-kit",
    "keylogger", "ransomware", "remote-access-trojan", "resource-exploitation",
    "rogue-security-software", "rootkit", "screen-capture", "spyware", "trojan", "unknown", "virus",
    "webshell", "wiper", "worm"
};

/// Pattern type open vocabulary.
pub static PATTERN_TYPE_OV: phf::Set<&'static str> =
    phf::phf_set! { "pcre", "sigma", "snort", "stix", "suricata", "yara" };

/// Processor architecture open vocabulary.
pub static PROCESSOR_ARCHITECTURE_OV: phf::Set<&'static str> =
    phf::phf_set! { "alpha", "arm", "ia-64", "mips", "powerpc", "sparc", "x86", "x86-64" };

/// Region open vocabulary (UNSD M49 geoscheme).
pub static REGION_OV: phf::Set<&'static str> = phf::phf_set! {
    "africa", "americas", "antarctica", "asia", "australia-new-zealand", "caribbean",
    "central-america", "central-asia", "eastern-africa", "eastern-asia", "eastern-europe", "europe",
    "latin-america-caribbean", "melanesia", "micronesia", "middle-africa", "northern-africa",
    "northern-america", "northern-europe", "oceania", "polynesia", "south-america",
    "south-eastern-asia", "southern-africa", "southern-asia", "southern-europe", "western-africa",
    "western-asia", "western-europe"
};

/// Report type open vocabulary.
pub static REPORT_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "attack-pattern", "campaign", "identity", "incident", "indicator", "intrusion-set", "malware",
    "observed-data", "threat-actor", "threat-report", "tool", "vulnerability"
};

/// Threat actor role open vocabulary.
pub static THREAT_ACTOR_ROLE_OV: phf::Set<&'static str> = phf::phf_set! {
    "agent", "director", "independent", "infrastructure-architect", "infrastructure-operator",
    "malware-author", "sponsor"
};

/// Threat actor sophistication open vocabulary.
pub static THREAT_ACTOR_SOPHISTICATION_OV: phf::Set<&'static str> = phf::phf_set! { "advanced", "expert", "innovator", "intermediate", "minimal", "none", "strategic" };

/// Threat actor type open vocabulary.
pub static THREAT_ACTOR_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "activist", "competitor", "crime-syndicate", "criminal", "hacker", "insider-accidental",
    "insider-disgruntled", "nation-state", "private-sector", "sensationalist", "spy", "terrorist",
    "unknown"
};

/// Tool type open vocabulary.
pub static TOOL_TYPE_OV: phf::Set<&'static str> = phf::phf_set! {
    "credential-exploitation", "denial-of-service", "exploitation", "information-gathering",
    "network-capture", "remote-access", "unknown", "vulnerability-scanning"
};

/// Open vocabulary value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpenVocab<T: Clone> {
    /// Known standard value.
    Known(T),
    /// Extension value outside the known set.
    Extension(String),
}
