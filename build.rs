use std::{env, io};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=RSS_REGISTRY_SKIP_ADMIN_MANIFEST");

    // Build Windows resources: icon + manifest with requireAdministrator.
    if cfg!(target_os = "windows") && env::var_os("RSS_REGISTRY_SKIP_ADMIN_MANIFEST").is_none() {
        let mut res = winres::WindowsResource::new();
        res.set_icon("rss.ico");
        res.set_manifest_file("app.manifest");
        res.compile()?;
    }
    Ok(())
}
