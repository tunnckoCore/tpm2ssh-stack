use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmCapability {
    pub name: String,
    pub raw_name: String,
    pub value: Option<u32>,
    pub asymmetric: Option<bool>,
    pub symmetric: Option<bool>,
    pub hash: Option<bool>,
    pub object: Option<bool>,
    pub signing: Option<bool>,
    pub encrypting: Option<bool>,
    pub method: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandCapability {
    pub name: String,
    pub raw_name: String,
    pub value: Option<u32>,
    pub command_index: Option<u32>,
    pub nv: Option<bool>,
    pub extensive: Option<bool>,
    pub flushed: Option<bool>,
    pub c_handles: Option<u32>,
    pub r_handle: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccCurveCapability {
    pub name: String,
    pub raw_name: String,
    pub value: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedProperty {
    pub name: String,
    pub raw_name: String,
    pub raw: Option<u32>,
    pub value: Option<String>,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedBlock {
    header: String,
    inline_value: Option<String>,
    fields: BTreeMap<String, String>,
}

pub fn parse_algorithms(input: &str) -> Vec<AlgorithmCapability> {
    parse_named_blocks(input)
        .into_iter()
        .map(|block| {
            let name = normalize_name(&block.header);
            let raw_name = block.header.clone();
            AlgorithmCapability {
                name,
                raw_name,
                value: block.field("value").and_then(parse_u32),
                asymmetric: block.field("asymmetric").and_then(parse_bool_flag),
                symmetric: block.field("symmetric").and_then(parse_bool_flag),
                hash: block.field("hash").and_then(parse_bool_flag),
                object: block.field("object").and_then(parse_bool_flag),
                signing: block.field("signing").and_then(parse_bool_flag),
                encrypting: block.field("encrypting").and_then(parse_bool_flag),
                method: block.field("method").and_then(parse_bool_flag),
            }
        })
        .collect()
}

pub fn parse_commands(input: &str) -> Vec<CommandCapability> {
    parse_named_blocks(input)
        .into_iter()
        .map(|block| {
            let name = normalize_name(&block.header);
            let raw_name = block.header.clone();
            CommandCapability {
                name,
                raw_name,
                value: block.field("value").and_then(parse_u32),
                command_index: block.field("commandIndex").and_then(parse_u32),
                nv: block.field("nv").and_then(parse_bool_flag),
                extensive: block.field("extensive").and_then(parse_bool_flag),
                flushed: block.field("flushed").and_then(parse_bool_flag),
                c_handles: block.field("cHandles").and_then(parse_u32),
                r_handle: block.field("rHandle").and_then(parse_bool_flag),
            }
        })
        .collect()
}

pub fn parse_ecc_curves(input: &str) -> Vec<EccCurveCapability> {
    input
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('-') {
                return None;
            }

            let (name, value) = trimmed.split_once(':')?;
            Some(EccCurveCapability {
                name: normalize_name(name),
                raw_name: name.trim().to_string(),
                value: parse_u32(value),
            })
        })
        .collect()
}

pub fn parse_properties_fixed(input: &str) -> Vec<FixedProperty> {
    parse_named_blocks(input)
        .into_iter()
        .map(|block| {
            let name = normalize_name(&block.header);
            let raw_name = block.header.clone();
            FixedProperty {
                name,
                raw_name,
                raw: block.field("raw").and_then(parse_u32),
                value: block
                    .field("value")
                    .map(|value| value.trim_matches('"').to_string())
                    .or_else(|| block.inline_value.clone()),
                fields: block.fields,
            }
        })
        .collect()
}

fn parse_named_blocks(input: &str) -> Vec<NamedBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<NamedBlock> = None;

    for raw_line in input.lines() {
        let line = raw_line.trim_end();
        if line.trim().is_empty() {
            continue;
        }

        let is_top_level = !raw_line.chars().next().is_some_and(char::is_whitespace);
        if is_top_level {
            if let Some(block) = current.take() {
                blocks.push(block);
            }

            if let Some(header) = line.strip_suffix(':') {
                current = Some(NamedBlock {
                    header: header.trim().to_string(),
                    inline_value: None,
                    fields: BTreeMap::new(),
                });
                continue;
            }

            if let Some((header, value)) = line.split_once(':') {
                current = Some(NamedBlock {
                    header: header.trim().to_string(),
                    inline_value: Some(value.trim().trim_matches('"').to_string()),
                    fields: BTreeMap::new(),
                });
                continue;
            }
        }

        if let Some(block) = current.as_mut() {
            if let Some((key, value)) = line.trim().split_once(':') {
                block
                    .fields
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    if let Some(block) = current.take() {
        blocks.push(block);
    }

    blocks
}

impl NamedBlock {
    fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

fn normalize_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn parse_bool_flag(value: &str) -> Option<bool> {
    match value.trim().trim_matches('"').to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn parse_u32(value: &str) -> Option<u32> {
    let trimmed = value.trim().trim_matches('"');
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_algorithms, parse_commands, parse_ecc_curves, parse_properties_fixed};

    #[test]
    fn parses_algorithms_output() {
        let parsed = parse_algorithms(
            "ecc:\n  value:      0x23\n  asymmetric: 1\n  symmetric:  0\n  hash:       0\n  object:     1\n  signing:    1\n  encrypting: 1\n  method:     0\nhmac:\n  value:      0x5\n  asymmetric: 0\n  symmetric:  1\n  hash:       0\n  object:     0\n  signing:    1\n  encrypting: 0\n  method:     0\n",
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "ecc");
        assert_eq!(parsed[0].value, Some(0x23));
        assert_eq!(parsed[0].asymmetric, Some(true));
        assert_eq!(parsed[1].name, "hmac");
        assert_eq!(parsed[1].signing, Some(true));
    }

    #[test]
    fn parses_commands_output() {
        let parsed = parse_commands(
            "TPM2_CC_Create:\n  value: 0x153\n  commandIndex: 0x153\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\nTPM2_CC_Sign:\n  value: 0x15d\n  commandIndex: 0x15d\n  nv: 0\n  extensive: 0\n  flushed: 0\n  cHandles: 0x1\n  rHandle: 0\n",
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "tpm2_cc_create");
        assert_eq!(parsed[1].command_index, Some(0x15d));
    }

    #[test]
    fn parses_ecc_curve_output() {
        let parsed = parse_ecc_curves(
            r#"
            TPM2_ECC_NIST_P256: 0x3
            TPM2_ECC_NIST_P384: 0x4
            "#,
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "tpm2_ecc_nist_p256");
        assert_eq!(parsed[1].value, Some(0x4));
    }

    #[test]
    fn parses_fixed_properties_output() {
        let parsed = parse_properties_fixed(
            "TPM2_PT_FAMILY_INDICATOR:\n  raw: 0x322E3000\n  value: \"2.0\"\nTPM2_PT_MODES:\n  raw: 0x1\n  value: TPMA_MODES_FIPS_140_2\nTPM2_PT_INPUT_BUFFER:\n  raw: 0x400\n",
        );

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, "tpm2_pt_family_indicator");
        assert_eq!(parsed[0].value.as_deref(), Some("2.0"));
        assert_eq!(
            parsed[1].fields.get("value").map(String::as_str),
            Some("TPMA_MODES_FIPS_140_2")
        );
        assert_eq!(parsed[2].raw, Some(0x400));
    }
}
