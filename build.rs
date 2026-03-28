use std::io;

fn main() -> io::Result<()> {
    // Build Windows resources: icon + manifest with requireAdministrator.
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("rss.ico");
        res.set_manifest_file("app.manifest");
        res.compile()?;
    }
    Ok(())
}
