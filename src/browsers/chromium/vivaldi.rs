use super::base;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: "Vivaldi".into(),
            exe: "vivaldi.exe".into(),
            user_data_rel: r"Vivaldi\User Data".into(),
            root: crate::browsers::common::paths::DataRoot::Local,
            has_profiles: true,
        }
    );
    base::extract_for_browser("Vivaldi", &user_data, true)
}
