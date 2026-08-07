use super::base;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: "Opera".into(),
            exe: "opera.exe".into(),
            user_data_rel: r"Opera Software\Opera Stable".into(),
            root: crate::browsers::common::paths::DataRoot::Roaming,
            has_profiles: false,
        }
    );
    base::extract_for_browser("Opera", &user_data, false)
}
