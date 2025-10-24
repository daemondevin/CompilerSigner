use winresource::WindowsResource;

fn main() {
    if cfg!(target_os = "windows") {
        WindowsResource::new()
            .set_icon("CompilerSigner.ico")
            .set_version_info(winresource::VersionInfo::PRODUCTVERSION, 0x03000100)
            .set_version_info(winresource::VersionInfo::FILEVERSION, 0x03000100)
            .set("ProductName", "CompilerSigner")
            .set("FileDescription", "Portable Code Signing Utility")
            .set("CompanyName", "How Dumb, LLC")
            .set("LegalCopyright", "Copyleft (C) daemon.devin")
            .compile()
            .unwrap();
    }
}