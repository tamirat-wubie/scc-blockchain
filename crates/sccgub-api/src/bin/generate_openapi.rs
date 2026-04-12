use std::path::Path;

fn usage() -> ! {
    eprintln!(
        "Usage: cargo run -p sccgub-api --bin generate_openapi [-- --write <path> | --check <path>]"
    );
    std::process::exit(2);
}

fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

fn write_openapi(path: &Path) -> Result<(), String> {
    std::fs::write(path, sccgub_api::openapi::render_openapi_yaml())
        .map_err(|error| format!("failed to write {}: {}", path.display(), error))
}

fn check_openapi(path: &Path) -> Result<(), String> {
    let generated = sccgub_api::openapi::render_openapi_yaml();
    let checked_in = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {}", path.display(), error))?;

    if normalize(&generated) != normalize(&checked_in) {
        return Err(format!(
            "OpenAPI artifact at {} is out of date",
            path.display()
        ));
    }

    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => {
            print!("{}", sccgub_api::openapi::render_openapi_yaml());
        }
        (Some("--write"), Some(path), None) => {
            if let Err(error) = write_openapi(Path::new(&path)) {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }
        (Some("--check"), Some(path), None) => {
            if let Err(error) = check_openapi(Path::new(&path)) {
                eprintln!("{}", error);
                std::process::exit(1);
            }
        }
        _ => usage(),
    }
}
