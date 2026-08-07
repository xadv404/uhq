use super::base;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: "Brave".into(),
            exe: "brave.exe".into(),
            user_data_rel: r"BraveSoftware\Brave-Browser\User Data".into(),
            root: crate::browsers::common::paths::DataRoot::Local,
            has_profiles: true,
        }
    );
    base::extract_for_browser("Brave", &user_data, true)
}
