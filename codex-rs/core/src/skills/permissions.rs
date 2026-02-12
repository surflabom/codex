use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

use dirs::home_dir;
use dunce::canonicalize as canonicalize_path;
use serde::Deserialize;
use tracing::warn;

use crate::skills::model::SkillMetadata;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillSandboxPermissionPolicy {
    pub network: bool,
    pub fs_read: Vec<PathBuf>,
    pub fs_write: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SkillPermissionProfile {
    pub sandbox_policy: SkillSandboxPermissionPolicy,
    pub macos_seatbelt_permission_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub(crate) struct SkillManifestPermissions {
    #[serde(default)]
    pub(crate) network: bool,
    #[serde(default)]
    pub(crate) fs_read: Vec<String>,
    #[serde(default)]
    pub(crate) fs_write: Vec<String>,
    #[serde(default)]
    pub(crate) macos_preferences: Option<MacOsPreferencesValue>,
    #[serde(default)]
    pub(crate) macos_automation: Option<MacOsAutomationValue>,
    #[serde(default)]
    pub(crate) macos_accessibility: bool,
    #[serde(default)]
    pub(crate) macos_calendar: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub(crate) enum MacOsPreferencesValue {
    Bool(bool),
    Mode(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub(crate) enum MacOsAutomationValue {
    Bool(bool),
    BundleIds(Vec<String>),
}

pub(crate) fn compile_permission_profile(
    skill_dir: &Path,
    permissions: Option<SkillManifestPermissions>,
) -> Option<SkillPermissionProfile> {
    let permissions = permissions?;
    let sandbox_policy = SkillSandboxPermissionPolicy {
        network: permissions.network,
        fs_read: normalize_permission_paths(skill_dir, &permissions.fs_read, "permissions.fs_read"),
        fs_write: normalize_permission_paths(
            skill_dir,
            &permissions.fs_write,
            "permissions.fs_write",
        ),
    };
    let macos_seatbelt_permission_file = build_macos_seatbelt_permission_file(&permissions);
    let profile = SkillPermissionProfile {
        sandbox_policy,
        macos_seatbelt_permission_file,
    };
    if profile.sandbox_policy == SkillSandboxPermissionPolicy::default()
        && profile.macos_seatbelt_permission_file.is_empty()
    {
        None
    } else {
        Some(profile)
    }
}

pub fn permission_profile_for_executable<'a>(
    skills: &'a [SkillMetadata],
    executable: &Path,
) -> Option<&'a SkillPermissionProfile> {
    let executable = canonicalize_path(executable).unwrap_or_else(|_| executable.to_path_buf());
    let mut best_match: Option<(usize, &'a SkillPermissionProfile)> = None;

    for skill in skills {
        let Some(profile) = skill.permission_profile.as_ref() else {
            continue;
        };
        let Some(skill_dir) = skill.path.parent() else {
            continue;
        };
        let skill_dir = canonicalize_path(skill_dir).unwrap_or_else(|_| skill_dir.to_path_buf());
        if !executable.starts_with(&skill_dir) {
            continue;
        }

        let depth = skill_dir.components().count();
        match best_match {
            Some((best_depth, _)) if best_depth >= depth => {}
            _ => best_match = Some((depth, profile)),
        }
    }

    best_match.map(|(_, profile)| profile)
}

fn normalize_permission_paths(skill_dir: &Path, values: &[String], field: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    for value in values {
        let Some(path) = normalize_permission_path(skill_dir, value, field) else {
            continue;
        };
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    paths
}

fn normalize_permission_path(skill_dir: &Path, value: &str, field: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        warn!("ignoring {field}: value is empty");
        return None;
    }

    let expanded = expand_home(trimmed);
    let path = PathBuf::from(expanded);
    let absolute = if path.is_absolute() {
        path
    } else {
        skill_dir.join(path)
    };
    Some(canonicalize_path(&absolute).unwrap_or(absolute))
}

fn expand_home(path: &str) -> String {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home.to_string_lossy().to_string();
        }
        return path.to_string();
    }
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = home_dir()
    {
        return home.join(rest).to_string_lossy().to_string();
    }
    path.to_string()
}

#[cfg(target_os = "macos")]
fn build_macos_seatbelt_permission_file(permissions: &SkillManifestPermissions) -> String {
    use crate::seatbelt_permissions::MacOsAutomationPermission;
    use crate::seatbelt_permissions::MacOsPreferencesPermission;
    use crate::seatbelt_permissions::MacOsSeatbeltProfileExtensions;
    use crate::seatbelt_permissions::build_seatbelt_extensions;

    let extensions = MacOsSeatbeltProfileExtensions {
        macos_preferences: resolve_macos_preferences_permission(
            permissions.macos_preferences.as_ref(),
        ),
        macos_automation: resolve_macos_automation_permission(
            permissions.macos_automation.as_ref(),
        ),
        macos_accessibility: permissions.macos_accessibility,
        macos_calendar: permissions.macos_calendar,
    };
    build_seatbelt_extensions(&extensions).policy
}

#[cfg(target_os = "macos")]
fn resolve_macos_preferences_permission(
    value: Option<&MacOsPreferencesValue>,
) -> crate::seatbelt_permissions::MacOsPreferencesPermission {
    use crate::seatbelt_permissions::MacOsPreferencesPermission;

    match value {
        Some(MacOsPreferencesValue::Bool(true)) => MacOsPreferencesPermission::ReadOnly,
        Some(MacOsPreferencesValue::Bool(false)) => MacOsPreferencesPermission::None,
        Some(MacOsPreferencesValue::Mode(mode)) => {
            let mode = mode.trim();
            if mode.eq_ignore_ascii_case("readonly") || mode.eq_ignore_ascii_case("read-only") {
                MacOsPreferencesPermission::ReadOnly
            } else if mode.eq_ignore_ascii_case("readwrite")
                || mode.eq_ignore_ascii_case("read-write")
            {
                MacOsPreferencesPermission::ReadWrite
            } else {
                warn!(
                    "ignoring permissions.macos_preferences: expected true/false, readonly, or readwrite"
                );
                MacOsPreferencesPermission::None
            }
        }
        None => MacOsPreferencesPermission::None,
    }
}

#[cfg(target_os = "macos")]
fn resolve_macos_automation_permission(
    value: Option<&MacOsAutomationValue>,
) -> crate::seatbelt_permissions::MacOsAutomationPermission {
    use crate::seatbelt_permissions::MacOsAutomationPermission;

    match value {
        Some(MacOsAutomationValue::Bool(true)) => MacOsAutomationPermission::All,
        Some(MacOsAutomationValue::Bool(false)) => MacOsAutomationPermission::None,
        Some(MacOsAutomationValue::BundleIds(bundle_ids)) => {
            let bundle_ids = bundle_ids
                .iter()
                .map(|bundle_id| bundle_id.trim())
                .filter(|bundle_id| !bundle_id.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<String>>();
            if bundle_ids.is_empty() {
                MacOsAutomationPermission::None
            } else {
                MacOsAutomationPermission::BundleIds(bundle_ids)
            }
        }
        None => MacOsAutomationPermission::None,
    }
}

#[cfg(not(target_os = "macos"))]
fn build_macos_seatbelt_permission_file(_: &SkillManifestPermissions) -> String {
    String::new()
}

#[cfg(test)]
mod tests {
    use super::SkillManifestPermissions;
    use super::SkillPermissionProfile;
    use super::compile_permission_profile;
    use super::permission_profile_for_executable;
    use crate::skills::model::SkillMetadata;
    use codex_protocol::protocol::SkillScope;
    use pretty_assertions::assert_eq;
    use std::fs;

    #[test]
    fn compile_permission_profile_normalizes_paths() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let skill_dir = tempdir.path().join("skill");
        fs::create_dir_all(skill_dir.join("scripts")).expect("skill dir");
        let read_dir = skill_dir.join("data");
        fs::create_dir_all(&read_dir).expect("read dir");

        let profile = compile_permission_profile(
            &skill_dir,
            Some(SkillManifestPermissions {
                network: true,
                fs_read: vec![
                    "./data".to_string(),
                    "./data".to_string(),
                    "scripts/../data".to_string(),
                ],
                fs_write: vec!["./output".to_string()],
                ..Default::default()
            }),
        )
        .expect("profile");

        assert!(profile.sandbox_policy.network);
        assert_eq!(profile.sandbox_policy.fs_read, vec![read_dir]);
        assert_eq!(
            profile.sandbox_policy.fs_write,
            vec![skill_dir.join("output")]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn compile_permission_profile_builds_macos_permission_file() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let skill_dir = tempdir.path().join("skill");
        fs::create_dir_all(&skill_dir).expect("skill dir");

        let profile = compile_permission_profile(
            &skill_dir,
            Some(SkillManifestPermissions {
                macos_preferences: Some(super::MacOsPreferencesValue::Mode(
                    "readwrite".to_string(),
                )),
                macos_automation: Some(super::MacOsAutomationValue::BundleIds(vec![
                    "com.apple.Notes".to_string(),
                ])),
                macos_accessibility: true,
                macos_calendar: true,
                ..Default::default()
            }),
        )
        .expect("profile");

        assert!(
            profile
                .macos_seatbelt_permission_file
                .contains("(allow user-preference-write)")
        );
        assert!(
            profile
                .macos_seatbelt_permission_file
                .contains("(appleevent-destination \"com.apple.Notes\")")
        );
        assert!(
            profile
                .macos_seatbelt_permission_file
                .contains("com.apple.axserver")
        );
    }

    #[test]
    fn permission_profile_for_executable_matches_skill_scoped_binary() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let skill_dir = tempdir.path().join("skill");
        fs::create_dir_all(skill_dir.join("scripts")).expect("scripts dir");
        let script_path = skill_dir.join("scripts").join("run.sh");
        fs::write(&script_path, "#!/bin/sh\nexit 0\n").expect("script");

        let profile = SkillPermissionProfile::default();
        let skill = SkillMetadata {
            name: "demo".to_string(),
            description: "demo".to_string(),
            short_description: None,
            interface: None,
            dependencies: None,
            policy: None,
            permission_profile: Some(profile),
            path: skill_dir.join("SKILL.md"),
            scope: SkillScope::User,
        };

        assert!(
            permission_profile_for_executable(&[skill], &script_path).is_some(),
            "expected skill-local executable to match profile"
        );
    }
}
