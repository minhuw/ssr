use anyhow::{anyhow, Result};
use clap::builder::TypedValueParser;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreList(Vec<usize>);

impl FromStr for CoreList {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut cores = Vec::new();

        if s.is_empty() {
            return Ok(CoreList(cores));
        }

        for part in s.split(',') {
            let part = part.trim();

            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() != 2 {
                    return Err(anyhow!("invalid range format: {}", part));
                }

                let start: usize = range[0]
                    .parse()
                    .map_err(|e| anyhow!("invalid start of range '{}': {}", range[0], e))?;
                let end: usize = range[1]
                    .parse()
                    .map_err(|e| anyhow!("invalid end of range '{}': {}", range[1], e))?;

                if end < start {
                    return Err(anyhow!("invalid range: {} is greater than {}", start, end));
                }

                cores.extend(start..=end);
            } else {
                let core: usize = part
                    .parse()
                    .map_err(|e| anyhow!("invalid core number '{}': {}", part, e))?;
                cores.push(core);
            }
        }

        cores.sort_unstable();
        cores.dedup();

        Ok(CoreList(cores))
    }
}

// Implement the value parser for clap
#[derive(Clone, Debug)]
pub struct CoreListValueParser;

impl TypedValueParser for CoreListValueParser {
    type Value = CoreList;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        let s = value.to_str().ok_or_else(|| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidUtf8,
                "core list contains invalid UTF-8",
            )
        })?;

        CoreList::from_str(s).map_err(|e| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                format!("invalid core list: {}", e),
            )
        })
    }
}

impl CoreList {
    pub fn parser() -> CoreListValueParser {
        CoreListValueParser
    }

    pub fn cores(&self) -> &[usize] {
        &self.0
    }

    pub fn into_cores(self) -> Vec<usize> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &usize> {
        self.0.iter()
    }

    /// Convert the core list to a bitmap where each set bit represents a core.
    /// Returns an error if any core index is >= 64.
    pub fn to_bitmap(&self) -> Result<u64> {
        let mut bitmap = 0u64;

        for &core in &self.0 {
            if core >= 64 {
                return Err(anyhow!(
                    "core index {} is too large for u64 bitmap (max: 63)",
                    core
                ));
            }
            bitmap |= 1u64 << core;
        }

        Ok(bitmap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        assert_eq!("".parse::<CoreList>().unwrap().cores().len(), 0);
    }

    #[test]
    fn test_parse_single_core() {
        assert_eq!("0".parse::<CoreList>().unwrap().cores(), &[0]);
        assert_eq!("5".parse::<CoreList>().unwrap().cores(), &[5]);
    }

    #[test]
    fn test_parse_multiple_cores() {
        assert_eq!("0,1,2".parse::<CoreList>().unwrap().cores(), &[0, 1, 2]);
        assert_eq!("0, 1, 2".parse::<CoreList>().unwrap().cores(), &[0, 1, 2]);
    }

    #[test]
    fn test_parse_range() {
        assert_eq!("0-2".parse::<CoreList>().unwrap().cores(), &[0, 1, 2]);
        assert_eq!("1-3".parse::<CoreList>().unwrap().cores(), &[1, 2, 3]);
    }

    #[test]
    fn test_parse_mixed() {
        assert_eq!(
            "0,2-4,6".parse::<CoreList>().unwrap().cores(),
            &[0, 2, 3, 4, 6]
        );
        assert_eq!(
            "0-2,4,6-8".parse::<CoreList>().unwrap().cores(),
            &[0, 1, 2, 4, 6, 7, 8]
        );
    }

    #[test]
    fn test_parse_duplicates() {
        assert_eq!("1,1,1".parse::<CoreList>().unwrap().cores(), &[1]);
        assert_eq!("1-3,2,3".parse::<CoreList>().unwrap().cores(), &[1, 2, 3]);
    }

    #[test]
    fn test_invalid_input() {
        assert!("invalid".parse::<CoreList>().is_err());
        assert!("1-".parse::<CoreList>().is_err());
        assert!("-1".parse::<CoreList>().is_err());
        assert!("3-1".parse::<CoreList>().is_err());
    }

    #[test]
    fn test_to_bitmap() {
        // Test single core
        assert_eq!("0".parse::<CoreList>().unwrap().to_bitmap().unwrap(), 1);
        assert_eq!("1".parse::<CoreList>().unwrap().to_bitmap().unwrap(), 2);

        // Test multiple cores
        assert_eq!("0,1".parse::<CoreList>().unwrap().to_bitmap().unwrap(), 3);
        assert_eq!("0,2".parse::<CoreList>().unwrap().to_bitmap().unwrap(), 5);

        // Test range
        assert_eq!("0-2".parse::<CoreList>().unwrap().to_bitmap().unwrap(), 7);

        // Test mixed
        assert_eq!(
            "0,2-4,6".parse::<CoreList>().unwrap().to_bitmap().unwrap(),
            0b1011111
        );

        // Test error on too large core
        assert!("65".parse::<CoreList>().unwrap().to_bitmap().is_err());
        assert!("0,64".parse::<CoreList>().unwrap().to_bitmap().is_err());
        assert!("63".parse::<CoreList>().unwrap().to_bitmap().is_ok());
    }
}
